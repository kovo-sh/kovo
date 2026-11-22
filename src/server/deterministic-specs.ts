/**
 * Deterministic replay-spec synthesis for the in-product engine.
 *
 * The engine observes a differential probe signal (see surface-engine.ts) and builds the same
 * declarative replay shapes the benchmark pipeline proved out, but only from what the probe
 * actually observed: the endpoint, parameter location, identifiers and anomaly details. No
 * benchmark manifest or app-specific literal is consulted.
 *
 * Every builder is pure. Callers validate the returned record with
 * `declarativeReplaySpecSchema` and then let ReplayVerifier decide whether it is real, so a
 * builder mistake costs a bounded replay and can never persist an unverified finding.
 */
import { randomBytes } from 'node:crypto'
import type { DifferentialProbeClass, DifferentialResult, SurfaceParamLocation } from './surface-engine.ts'

export interface EngineParam {
  name: string
  location: SurfaceParamLocation
  isObjectId?: boolean
  isCsrf?: boolean
}

export interface EngineEndpoint {
  id: string
  origin: string
  method: string
  pathTemplate: string
  params: EngineParam[]
  riskScore?: number
  sinkKinds?: string[]
  source?: string
}

export type EngineIntent =
  | 'authz' | 'sqli' | 'xxe' | 'ssrf' | 'traversal' | 'redirect' | 'xss' | 'graphql'
  | 'mass_assignment' | 'cache' | 'stored_xss' | 'csrf' | 'workflow' | 'webhook' | 'auth_protocol' | 'secret_disclosure'

export interface EngineHypothesis {
  key: string
  endpoint: EngineEndpoint
  probeClass: DifferentialProbeClass
  intent: EngineIntent
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  /** Probe/replay path. Object-level authz hypotheses keep a `{{id}}` placeholder. */
  pathAndQuery: string
  param?: EngineParam
  location?: SurfaceParamLocation
  ownerPersona?: string
  otherPersona?: string
  resourceIds?: string[]
  jsonBody?: Record<string, unknown>
  formBody?: Record<string, string>
  xmlTemplate?: string
  graphqlQuery?: string
  baselineValue?: string
  candidateFields?: string[]
  candidateValues?: Record<string, string | boolean | number>
  ssrfParams?: string[]
  functionLevel?: boolean
  idParamName?: string
  /** Second-order SSRF: route that re-triggers the stored fetch, with `{{resource_id}}`. */
  triggerPath?: string
  /** Second-order XSS / CSRF: downstream read route. */
  readPath?: string
  /** Bound session handle used for CSRF replay (no Authorization/Cookie headers). */
  session?: string
  graphqlRoots?: string[]
  graphqlSeedsByRoot?: Record<string, string[]>
  stateField?: string
  bodyField?: string
  createReadTemplate?: string
  secretScan?: boolean
  viewerPersona?: string
  csrfBind?: boolean
  risk: number
  notes?: string[]
}

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface SynthesizedEngineSpec {
  kind: string
  /** Canonical class label used for attribution/dedupe (benchmark-compatible spelling). */
  vulnClass: string
  endpoint: string
  spec: Record<string, unknown>
}

interface RequestParts {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  pathAndQuery: string
  headers?: Record<string, string>
  jsonBody?: unknown
  textBody?: string
}

const jqStr = (v: string) => JSON.stringify(v)
const is2xx = (stepId: string) => `(.steps.${stepId}.status >= 200 and .steps.${stepId}.status < 300)`
const nonTrivial = (stepId: string, minBytes = 3) =>
  `(((${is2xx(stepId)})) and (((.steps.${stepId}.body | length) > ${minBytes}) or (((.steps.${stepId}.json | type) == "object") and (((.steps.${stepId}.json | keys | length) >= 2)))))`

function baseFields(
  origin: string,
  title: string,
  cwe: string,
  category: string,
  severity: Severity,
  jq: string,
) {
  return {
    version: 1 as const,
    origin,
    title: title.slice(0, 200),
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

function stepOf(
  origin: string,
  id: string,
  role: 'setup' | 'control' | 'probe' | 'cleanup',
  description: string,
  parts: RequestParts,
  persona?: string | null,
  extra: Record<string, unknown> = {},
  expectedStatus?: number[],
) {
  return {
    id,
    role,
    description,
    ...(expectedStatus ? { expectedStatus } : {}),
    request: {
      origin,
      method: parts.method,
      pathAndQuery: parts.pathAndQuery,
      ...(parts.headers ? { headers: parts.headers } : {}),
      ...(parts.jsonBody !== undefined ? { jsonBody: parts.jsonBody } : {}),
      ...(parts.textBody !== undefined ? { textBody: parts.textBody } : {}),
      ...(persona ? { persona } : {}),
      followRedirects: false,
      ...extra,
    },
  }
}

function appendQuery(pathAndQuery: string, name: string, rawValue: string, encodeValue = true): string {
  const sep = pathAndQuery.includes('?') ? '&' : '?'
  const encodedValue = encodeValue && !rawValue.includes('{{') ? encodeURIComponent(rawValue) : rawValue
  return `${pathAndQuery}${sep}${encodeURIComponent(name)}=${encodedValue}`
}

function fillId(pathAndQuery: string, id: string): string {
  return pathAndQuery.replaceAll('{{id}}', encodeURIComponent(id))
}

/**
 * A syntactically valid identifier that must not resolve to any real object. Used as a negative
 * control so a route that ignores its identifier (and serves the caller's own session object)
 * cannot be mistaken for an object-level authorization failure.
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

/** Build one request for the hypothesis with `value` placed in its parameter. */
export function requestParts(hyp: EngineHypothesis, value: string): RequestParts | null {
  const param = hyp.param
  const location = hyp.location ?? param?.location
  if (!param || !location) return null
  const path = hyp.pathAndQuery
  const siblings = hyp.jsonBody && location !== 'json' ? { ...hyp.jsonBody } : (hyp.jsonBody ?? {})
  switch (location) {
    case 'query':
      return { method: 'GET', pathAndQuery: appendQuery(path, param.name, value) }
    case 'path':
      return { method: hyp.method === 'GET' ? 'GET' : hyp.method, pathAndQuery: path.replaceAll('{{val}}', encodeURIComponent(value)) }
    case 'header':
      return { method: hyp.method, pathAndQuery: path, headers: { [param.name]: value } }
    case 'json':
      return {
        method: hyp.method === 'GET' ? 'POST' : hyp.method,
        pathAndQuery: path,
        jsonBody: { ...siblings, [param.name]: value },
      }
    case 'form': {
      const all = { ...(hyp.formBody ?? {}), ...siblings, [param.name]: value }
      return {
        method: hyp.method === 'GET' ? 'POST' : hyp.method,
        pathAndQuery: path,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        textBody: Object.entries(all).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
      }
    }
    case 'xml': {
      const template = hyp.xmlTemplate ?? `<request><${param.name}>{{val}}</${param.name}></request>`
      return {
        method: 'POST',
        pathAndQuery: path,
        headers: { 'Content-Type': 'application/xml' },
        textBody: template.replaceAll('{{val}}', value),
      }
    }
    case 'graphql_var': {
      if (!hyp.graphqlQuery) return null
      return {
        method: 'POST',
        pathAndQuery: path,
        jsonBody: { query: hyp.graphqlQuery, variables: { ...siblings, [param.name]: value } },
      }
    }
    default:
      return null
  }
}

// ---------------------------------------------------------------------------------------------
// Authorization matrix -> http_chain
// ---------------------------------------------------------------------------------------------

interface MatrixRow {
  resourceId?: unknown
  actor?: unknown
  status?: unknown
  bodyBytes?: unknown
  bodySha256?: unknown
  similarityToOwner?: unknown
  accessible?: unknown
}

const NEGATIVE_CONTROL_STATUS = [400, 401, 403, 404, 405, 409, 410, 422]

function matchesOwnerJq(): string {
  return `((.steps.p1.body == .steps.c1.body) or (.steps.c1.json as $c | .steps.p1.json as $p | ` +
    `(($c | type) == "object") and (([$c | keys[]] | length) > 0) and ` +
    `(([($c | to_entries[]) | select($p[.key] == .value)] | length) == ([$c | keys[]] | length))) or ` +
    `((.steps.c1.json as $c | .steps.p1.json as $p | ($c | type) == "array" and ($p | type) == "array") and ` +
    `((.steps.c1.body | length) > 3) and (.steps.p1.body == .steps.c1.body)))`
}

function negativeControlJq(mutating: boolean): string {
  if (mutating) return `((.steps.c2.status >= 400) and (.steps.c2.status < 500))`
  return `(((.steps.c2.status >= 400) and (.steps.c2.status < 500)) or ((${is2xx('c2')}) and (.steps.c2.body != .steps.c1.body) and ((.steps.c2.body | length) > 2)))`
}

function synthAuthz(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const owner = hyp.ownerPersona
  const other = hyp.otherPersona
  if (!owner || !other) return []
  const sensitiveRead = hyp.method === 'GET' && /(?:^|[/_.-])(?:tokens?|keys?|secrets?|audit|auditlog|activity|logs?|config|export|apikeys?|links?|integrations?)(?:$|[/_.-])/i.test(hyp.endpoint.pathTemplate)
  // A function-level sensitive list (admin audit log, token inventory) is only reportable when the
  // probe actually observed a credential marker. A generic admin listing that merely returns audit
  // rows is real access-control debt but not the disclosure class this spec claims.
  if (sensitiveRead && hyp.functionLevel && !result.anomalies.some(anomaly => anomaly.type === 'secret_disclosed')) return []
  const cwe = sensitiveRead ? 'CWE-200' : 'CWE-639'
  const category = sensitiveRead ? 'information-disclosure' : 'broken-access-control'
  const title = sensitiveRead ? 'Cross-actor sensitive-data read' : 'Cross-actor object or function access'
  const vulnClass = sensitiveRead ? 'info_disclosure' : (hyp.functionLevel ? 'bfla' : 'bola')
  const matrix = Array.isArray(result.details.matrix) ? result.details.matrix as MatrixRow[] : null
  const hits = result.anomalies
    .filter(a => a.type === 'unauthorized_access')
    .sort((a, b) => {
      const ga = String(a.method ?? 'GET') === 'GET' ? 0 : 1
      const gb = String(b.method ?? 'GET') === 'GET' ? 0 : 1
      if (ga !== gb) return ga - gb
      return Number(b.similarityToOwner ?? 0) - Number(a.similarityToOwner ?? 0)
    })
  if (hits.length === 0) return []
  const out: SynthesizedEngineSpec[] = []
  const seen = new Set<string>()

  for (const hit of hits) {
    const id = String(hit.resourceId ?? '')
    const method = String(hit.method ?? 'GET')
    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) continue
    const mutating = method !== 'GET'
    const functionLevel = hit.functionLevel === true || hyp.functionLevel === true
    const key = `${method}|${functionLevel ? 'fn' : id}`
    if (seen.has(key)) continue
    seen.add(key)
    if (!functionLevel && !/^[A-Za-z0-9_.:-]{1,128}$/.test(id)) continue

    const probeActor = hit.actor === 'anonymous' ? 'anonymous' : 'other_persona'
    let ownerOk = true
    let probeOk = true
    if (matrix) {
      const idRows = functionLevel ? matrix : matrix.filter(r => String(r.resourceId ?? '') === id)
      const ownerRow = idRows.find(r => r.actor === 'owner')
      const probeRow = idRows.find(r => r.actor === probeActor)
      if (!ownerRow || ownerRow.accessible !== true || typeof ownerRow.status !== 'number' || ownerRow.status < 200 || ownerRow.status >= 300) ownerOk = false
      else if (typeof ownerRow.bodyBytes === 'number' && ownerRow.bodyBytes <= (mutating ? 12 : 2)) ownerOk = false
      if (!probeRow || probeRow.accessible !== true) probeOk = false
      else if (!mutating && Number(probeRow.similarityToOwner ?? hit.similarityToOwner ?? 0) < 0.7) probeOk = false
      const anonRow = idRows.find(r => r.actor === 'anonymous')
      // A sensitive-data route readable by anonymous callers is still a disclosure target; the
      // public-data veto exists to suppress ordinary public catalogs, not credential/audit reads.
      if (!mutating && !sensitiveRead && anonRow?.accessible === true && ownerRow) {
        const sameBody = typeof anonRow.bodySha256 === 'string' && anonRow.bodySha256 === ownerRow.bodySha256
        const similar = Number(anonRow.similarityToOwner ?? 0) >= 0.7
        if (sameBody || similar) ownerOk = false
      }
    }
    if (!ownerOk || !probeOk) continue

    const bodyTemplate = hit.bodyTemplate !== undefined && hit.bodyTemplate !== null
      ? hit.bodyTemplate
      : (hyp.jsonBody ?? {})
    const realPath = functionLevel ? hyp.pathAndQuery : fillId(hyp.pathAndQuery, id)
    const parts: RequestParts = {
      method: method as RequestParts['method'],
      pathAndQuery: realPath,
      ...(mutating ? { jsonBody: bodyTemplate } : {}),
    }
    const stepExtra = mutating && hyp.csrfBind ? { csrfBind: true } : {}
    const probePersona = hit.actor === 'anonymous' ? null : other
    const neg = functionLevel ? null : negativeControlJq(mutating)
    const ownerJq = nonTrivial('c1', mutating ? 12 : 3)
    const probeJq = nonTrivial('p1', mutating ? 12 : 3)
    const jq = `{ controlPassed: ((${ownerJq})${neg ? ` and (${neg})` : ''}), ` +
      `confirmed: ((${probeJq})${neg ? ` and (${neg})` : ''} and (${matchesOwnerJq()})), ` +
      `observed: ("probe status=" + (.steps.p1.status | tostring)${neg ? ' + " bogus status=" + (.steps.c2.status | tostring)' : ''}), ` +
      'expected: "non-owner denied" }'
    const steps: Array<Record<string, unknown>> = []
    if (!functionLevel) {
      const negativeId = matrix === null ? `guardian-none-${randomBytes(5).toString('hex')}` : bogusIdFor(id)
      steps.push(stepOf(
        hyp.endpoint.origin, 'c2', 'control',
        `Authorized actor addresses a nonexistent identifier (${negativeId})`,
        {
          method: method as RequestParts['method'],
          pathAndQuery: fillId(hyp.pathAndQuery, negativeId),
          ...(mutating ? { jsonBody: bodyTemplate } : {}),
        },
        owner, stepExtra, NEGATIVE_CONTROL_STATUS,
      ))
    }
    steps.push(stepOf(hyp.endpoint.origin, 'c1', 'control', 'Authorized actor performs the request', parts, owner, stepExtra))
    steps.push(stepOf(hyp.endpoint.origin, 'p1', 'probe', `${probePersona ? 'Lower-privileged actor' : 'Unauthenticated caller'} performs the same request`, parts, probePersona, stepExtra))
    out.push({
      kind: 'http_chain',
      vulnClass,
      endpoint: hyp.endpoint.pathTemplate,
      spec: {
        ...baseFields(hyp.endpoint.origin, title, cwe, category, sensitiveRead ? 'medium' : 'high', jq),
        kind: 'http_chain',
        steps,
      },
    })
  }
  return out
}

// ---------------------------------------------------------------------------------------------
// SQL injection
// ---------------------------------------------------------------------------------------------

function booleanStyle(style: string): { quoteStyle: 'single' | 'double' | 'numeric'; valueTemplate?: string } {
  switch (style) {
    case 'numeric': return { quoteStyle: 'numeric' }
    case 'double_quote': return { quoteStyle: 'double' }
    case 'single_quote': return { quoteStyle: 'single' }
    case 'or_branch': return { quoteStyle: 'single', valueTemplate: "{{baseline}}' OR {{sql_expr}}-- -" }
    case 'single_paren': return { quoteStyle: 'single', valueTemplate: "{{baseline}}') AND {{sql_expr}}-- -" }
    case 'single_double_paren': return { quoteStyle: 'single', valueTemplate: "{{baseline}}')) AND {{sql_expr}}-- -" }
    case 'like_breakout': return { quoteStyle: 'single', valueTemplate: "{{baseline}}%' AND {{sql_expr}}-- -" }
    case 'order_by': return { quoteStyle: 'single', valueTemplate: '{{baseline}} ORDER BY (CASE WHEN ({{sql_expr}}) THEN 1 ELSE 2 END)-- -' }
    default: return { quoteStyle: 'single' }
  }
}

const jqBoolean = '{ controlPassed: (.sqlDiff.controlPassed == true), confirmed: (.sqlDiff.passed == true), observed: ("passed=" + (.sqlDiff.passed | tostring)), expected: "boolean differential holds" }'

function synthSqlBoolean(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  if (!hyp.param || !hyp.location) return []
  const base = {
    ...baseFields(hyp.endpoint.origin, 'Boolean-based SQL injection differential', 'CWE-89', 'injection-input', 'high', jqBoolean),
    kind: 'sql_boolean_diff',
    targetOrigin: hyp.endpoint.origin,
    method: hyp.method,
    pathAndQuery: hyp.pathAndQuery,
    ...(hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}),
    ...(hyp.location === 'json' || hyp.location === 'form' ? { jsonBody: (hyp.jsonBody ?? {}) } : {}),
    ...(hyp.location === 'xml' && hyp.xmlTemplate ? { xmlTemplate: hyp.xmlTemplate } : {}),
    ...(hyp.location === 'graphql_var' && hyp.graphqlQuery ? { graphqlQuery: hyp.graphqlQuery, jsonBody: { variables: (hyp.jsonBody ?? {}) } } : {}),
    paramName: hyp.param.name,
    paramLocation: hyp.location,
    baselineValue: hyp.baselineValue ?? '1',
  }
  const make = (styleName: string): SynthesizedEngineSpec => {
    const style = booleanStyle(styleName)
    return {
      kind: 'sql_boolean_diff',
      vulnClass: 'sqli',
      endpoint: hyp.endpoint.pathTemplate,
      spec: {
        ...base,
        quoteStyle: style.quoteStyle,
        ...(style.valueTemplate ? { valueTemplate: style.valueTemplate } : {}),
      },
    }
  }
  const hit = result.anomalies.find(a => a.type === 'boolean_differential')
  if (hit) {
    const style = String(hit.style ?? 'single_quote')
    const out: SynthesizedEngineSpec[] = []
    const push = (candidate: SynthesizedEngineSpec) => {
      if (!out.some(existing => JSON.stringify(existing.spec) === JSON.stringify(candidate.spec))) out.push(candidate)
    }
    push(make(style))
    // A LIKE-wrapped search needs a broad baseline to make the true/false branch differ enough
    // for the verifier's randomized rounds; try the observed value plus short common terms.
    for (const baseline of ['a', 'e', '1']) {
      const candidate = make(style)
      candidate.spec.baselineValue = baseline
      push(candidate)
    }
    for (const fallback of ['single_quote', 'numeric', 'or_branch']) push(make(fallback))
    return out
  }
  if (!result.anomalies.some(a => a.type === 'db_error_fingerprint')) return []
  if (hyp.location === 'graphql_var') return []
  const out: SynthesizedEngineSpec[] = [{
    kind: 'sql_boolean_diff',
    vulnClass: 'sqli',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...base,
      baselineValue: "x' OR 1=1-- -",
      quoteStyle: 'single',
      valueTemplate: "x' OR {{sql_expr}}-- -",
    },
  }]
  for (const style of ['single_quote', 'numeric', 'double_quote', 'or_branch']) out.push(make(style))
  return out
}

// ---------------------------------------------------------------------------------------------
// XML external entity
// ---------------------------------------------------------------------------------------------

const xmlBenign = '<?xml version="1.0" encoding="UTF-8"?><guardian><ping>ok</ping></guardian>'
const xxeBodies: Record<string, string> = {
  general_entity: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY gxxe SYSTEM "{{canary_url}}">]><root>&gxxe;</root>',
  param_entity: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % gxxep SYSTEM "{{canary_url}}"> %gxxep;]><root>ok</root>',
  svg_dtd: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY svgx SYSTEM "{{canary_url}}">]><svg xmlns="http://www.w3.org/2000/svg"><text>&svgx;</text></svg>',
}
const canaryJq = (control: string) =>
  `{ controlPassed: (.steps.${control}.status < 500), confirmed: (.canary.triggered == true), observed: ("probeCallback=" + ((.canary.probeTriggered // false) | tostring)), expected: "no out-of-band callback" }`

function synthXxe(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'xxe_canary_callback')
  if (!hit) return []
  const body = xxeBodies[String(hit.variant)] ?? xxeBodies.general_entity
  const headers = { 'Content-Type': 'application/xml' }
  const method = hyp.method === 'GET' ? 'POST' : hyp.method
  return [{
    kind: 'http_chain',
    vulnClass: 'xxe',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'XML external entity injection (out-of-band callback)', 'CWE-611', 'xxe', 'high', canaryJq('c1')),
      kind: 'http_chain',
      steps: [
        stepOf(hyp.endpoint.origin, 'c1', 'control', 'Benign XML document', { method, pathAndQuery: hyp.pathAndQuery, headers, textBody: xmlBenign }, hyp.ownerPersona),
        stepOf(hyp.endpoint.origin, 'p1', 'probe', 'XML document with external entity to Guardian canary', { method, pathAndQuery: hyp.pathAndQuery, headers, textBody: body }, hyp.ownerPersona),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// SSRF
// ---------------------------------------------------------------------------------------------

function synthSsrf(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const direct = result.anomalies.find(a => a.type === 'canary_callback' && a.variant === 'http')
  if (!direct) return []
  if (hyp.triggerPath) {
    const control = requestParts(hyp, 'http://guardian-control.invalid/')
    const probe = requestParts(hyp, '{{canary_url}}')
    if (!control || !probe) return []
    const trigger = hyp.triggerPath.replace('{{id}}', '{{resource_id}}')
    const steps = [
      stepOf(hyp.endpoint.origin, 'c1', 'control', 'Register a benign URL (no callback expected)', control, hyp.ownerPersona),
      {
        ...stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Register the canary URL through the write route', probe, hyp.ownerPersona),
        extract: [{ varName: 'resource_id', from: 'json' as const, selector: 'id' }],
      },
      stepOf(hyp.endpoint.origin, 'p2', 'probe', 'Trigger the stored URL fetch', { method: 'POST', pathAndQuery: trigger, jsonBody: {} }, hyp.ownerPersona),
    ]
    return [{
      kind: 'http_chain',
      vulnClass: 'ssrf',
      endpoint: hyp.endpoint.pathTemplate,
      spec: {
        ...baseFields(hyp.endpoint.origin, 'Second-order server-side request forgery (stored URL fetched later)', 'CWE-918', 'ssrf', 'high', canaryJq('c1')),
        kind: 'http_chain',
        steps,
      },
    }]
  }
  const control = requestParts(hyp, 'http://guardian-control.invalid/')
  const probe = requestParts(hyp, '{{canary_url}}')
  if (!control || !probe) return []
  return [{
    kind: 'http_chain',
    vulnClass: 'ssrf',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'Server-side request forgery (out-of-band callback)', 'CWE-918', 'ssrf', 'high', canaryJq('c1')),
      kind: 'http_chain',
      steps: [
        stepOf(hyp.endpoint.origin, 'c1', 'control', 'Benign URL value (no callback expected)', control, hyp.ownerPersona),
        stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Guardian canary URL value', probe, hyp.ownerPersona),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// Path traversal
// ---------------------------------------------------------------------------------------------

function synthTraversal(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'path_traversal_escape')
  if (!hit || !hyp.param) return []
  const raw = String(hit.payload ?? '')
  if (!raw || raw.length > 200 || /[\r\n\0\\]/.test(raw)) return []
  const controlValue = `../guardian-none-${randomBytes(4).toString('hex')}.txt`
  const build = (value: string): RequestParts => {
    const parts = requestParts(hyp, value)
    if (parts) return parts
    return { method: hyp.method, pathAndQuery: hyp.pathAndQuery, jsonBody: { [hyp.param!.name]: value } }
  }
  const needle = typeof hit.contentNeedle === 'string' ? hit.contentNeedle.replace(/[\u0000-\u001f]/g, '').slice(0, 40) : ''
  const contentCheck = needle
    ? ` and (.steps.p1.body | contains(${jqStr(needle)}))`
    : ' and ((.steps.p1.body | length) > 0)'
  const jq = `{ controlPassed: ((.steps.c1.status < 200) or (.steps.c1.status >= 300)), ` +
    `confirmed: ((${is2xx('p1')})${contentCheck} and ((.steps.p1.body != .steps.c1.body) or (.steps.p1.status != .steps.c1.status))), ` +
    `observed: ("traversal status=" + (.steps.p1.status | tostring) + " bytes=" + (.steps.p1.body | length | tostring)), expected: "file names resolve inside the served root" }`
  return [{
    kind: 'http_chain',
    vulnClass: 'path_traversal',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'Path traversal escapes the served root (jail-escape read)', 'CWE-22', 'path-traversal', 'high', jq),
      kind: 'http_chain',
      steps: [
        stepOf(hyp.endpoint.origin, 'c1', 'control', 'Nonexistent sibling traversal control', build(controlValue), hyp.ownerPersona),
        stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Traversal payload that resolves outside the served root', build(raw), hyp.ownerPersona),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// Open redirect
// ---------------------------------------------------------------------------------------------

function canaryHostOf(payload: string): string | null {
  // The probe may hand back an absolute, protocol-relative or backslash-prefixed payload.
  const match = /([A-Za-z0-9.-]*gxr[A-Za-z0-9._-]*\.invalid)/i.exec(payload)
  return match?.[1] ?? null
}

function synthRedirect(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'open_redirect_differential')
  if (!hit || !hyp.param) return []
  const payload = String(hit.payload ?? '')
  const host = canaryHostOf(payload)
  if (!host) return []
  const control = requestParts(hyp, `/guardian-return-${randomBytes(4).toString('hex')}`)
  const probe = requestParts(hyp, payload)
  if (!control || !probe) return []
  const jq = `{ controlPassed: (.steps.c1.status < 400), ` +
    `confirmed: ((.steps.p1.status >= 300 and .steps.p1.status < 400) and ((.steps.p1.headers.location // "") | contains(${jqStr(host)}))), ` +
    'observed: ("location=" + ((.steps.p1.headers.location // "") | tostring)), expected: "redirect target stays on the registered origin" }'
  return [{
    kind: 'http_chain',
    vulnClass: 'open_redirect',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'Unvalidated redirect target (off-origin navigation)', 'CWE-601', 'open-redirect', 'low', jq),
      kind: 'http_chain',
      steps: [
        stepOf(hyp.endpoint.origin, 'c1', 'control', 'Benign relative return target', control, hyp.ownerPersona),
        stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Off-origin canary return target', probe, hyp.ownerPersona),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// GraphQL resolver authorization
// ---------------------------------------------------------------------------------------------

function synthGraphql(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const anomaly = result.anomalies.find(a =>
    a.type === 'graphql_cross_persona_access' || a.type === 'graphql_nested_bola' || a.type === 'graphql_bola_differential')
  if (!anomaly || !hyp.ownerPersona || !hyp.otherPersona) return []
  const field = typeof anomaly.field === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(anomaly.field) ? anomaly.field : null
  const nested = Array.isArray(anomaly.nestedPath)
    ? (anomaly.nestedPath as unknown[]).filter((x): x is string => typeof x === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(x))
    : []
  const recordedQueryRaw = typeof anomaly.query === 'string'
    ? anomaly.query
    : typeof anomaly.nestedQuery === 'string' ? anomaly.nestedQuery
      : typeof anomaly.operation === 'string' ? anomaly.operation : null
  const query = recordedQueryRaw && recordedQueryRaw.length <= 4000 &&
    /^\s*(?:[{(]|query\b|mutation\b|subscription\b|fragment\b)/.test(recordedQueryRaw) ? recordedQueryRaw : null
  if (!query) return []
  if (anomaly.sameRoot === false) return []
  const variables = anomaly.variables && typeof anomaly.variables === 'object' && !Array.isArray(anomaly.variables)
    ? anomaly.variables as Record<string, unknown> : {}
  const dataPath = field ? ['data', field, ...nested].map(p => `[${jqStr(p)}]`).join('') : '.data'
  const nestedLen = (id: string) => `((.steps.${id}.json${dataPath} // []) | length)`
  const errorsClean = (id: string) => `(((.steps.${id}.json.errors // []) | length) == 0)`
  const jq = `{ controlPassed: (${is2xx('c1')} and ${errorsClean('c1')} and (${nestedLen('c1')} >= 1)), ` +
    `confirmed: (${is2xx('p1')} and ${errorsClean('p1')} and (${nestedLen('p1')} >= 1) and (.steps.p1.json${dataPath} == .steps.c1.json${dataPath})), ` +
    `observed: ("nested records=" + (${nestedLen('p1')} | tostring)), expected: "nested owned data reaches only its owner" }`
  const step = (id: string, role: 'control' | 'probe', description: string, actor: string) =>
    stepOf(hyp.endpoint.origin, id, role, description, {
      method: 'POST',
      pathAndQuery: hyp.pathAndQuery,
      jsonBody: { query, ...(Object.keys(variables).length > 0 ? { variables } : {}) },
    }, actor)
  return [{
    kind: 'http_chain',
    vulnClass: 'graphql_bola',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'GraphQL resolver missing object authorization', 'CWE-639', 'broken-access-control', 'high', jq),
      kind: 'http_chain',
      steps: [
        step('c1', 'control', 'Owner queries the resolver', hyp.ownerPersona),
        step('p1', 'probe', 'Different actor queries the same resolver', hyp.otherPersona),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// Mass assignment (transition form)
// ---------------------------------------------------------------------------------------------

function massAssignmentValue(field: string, privileged: boolean, observed?: string | boolean | number): string | boolean | number | null {
  if (privileged && observed !== undefined && observed !== null) return observed
  if (/^(?:is|has|verified|admin|emailVerified|enabled|active|superuser|staff)/i.test(field)) return privileged
  if (privileged) {
    if (/role|admin|permission|privilege|scope/i.test(field)) return 'admin'
    if (/plan|tier/i.test(field)) return 'enterprise'
    if (/org|tenant|team|group|owner/i.test(field)) return '1'
    return 'guardian-privileged'
  }
  if (/role|permission|privilege|scope/i.test(field)) return 'user'
  if (/plan|tier/i.test(field)) return 'free'
  if (/org|tenant|team|group|owner/i.test(field)) return '0'
  return 'guardian-low'
}

function synthMassAssignment(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'mass_assignment')
  if (!hit || !hyp.ownerPersona) return []
  const hitField = String(hit.field ?? '')
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(hitField)) return []
  // The probe reports the first field that persisted; a sibling privileged field (tenant_id vs
  // owner_id) may be the one with a clean read-back. Try the observed field first, then the
  // hypothesis's other candidate fields.
  const fields = [...new Set([hitField, ...(hyp.candidateFields ?? [])])]
    .filter(field => /^[A-Za-z0-9_.-]{1,64}$/.test(field))
    .slice(0, 4)
  const method = (hyp.method === 'PUT' ? 'PUT' : hyp.method === 'PATCH' ? 'PATCH' : 'POST') as 'POST' | 'PUT' | 'PATCH'
  const readPath = hyp.pathAndQuery.split('?')[0]
  const read: RequestParts = { method: 'GET', pathAndQuery: readPath }
  const out: SynthesizedEngineSpec[] = []
  // Create-shaped mass assignment with a tenant/owner field: the overposted record is scoped to the
  // other tenant, so the owner's list cannot show it. Prove impact with a second-tenant read-back of
  // a unique marker that the caller's control write never placed in that tenant.
  const hasIdPath = /\/:|\{\{id\}\}|\{[^}]+\}/.test(hyp.pathAndQuery)
  if (!hasIdPath && method === 'POST' && hyp.otherPersona) {
    const scopedField = ['tenant_id', 'tenantId', 'org_id', 'orgId', 'team_id', 'teamId', 'owner_id', 'ownerId']
      .find(field => hyp.candidateValues?.[field] !== undefined)
    const expected = scopedField ? hyp.candidateValues?.[scopedField] : undefined
    if (scopedField && expected !== undefined) {
      const marker = randomBytes(5).toString('hex')
      const controlName = `guardian-ma-control-${marker}`
      const probeName = `guardian-ma-probe-${marker}`
      const nameField = (hyp.candidateFields ?? []).find(field => /^(?:name|title|label|subject)$/i.test(field)) ?? 'name'
      const body = (name: string, value: unknown) => ({ ...(hyp.jsonBody ?? {}), [nameField]: name, [scopedField]: value })
      const jq = `{ controlPassed: (${is2xx('c1')} and (${is2xx('p1')})), ` +
        `confirmed: ((${is2xx('p2')}) and (.steps.p2.body | contains(${jqStr(probeName)})) and (((.steps.p2.body | contains(${jqStr(controlName)})) | not))), ` +
        'observed: "cross-tenant created record visible to the other tenant", expected: "tenant-scoping fields must not be client-writable" }'
      out.push({
        kind: 'http_chain',
        vulnClass: 'mass_assignment',
        endpoint: hyp.endpoint.pathTemplate,
        spec: {
          ...baseFields(hyp.endpoint.origin, `Mass assignment of "${scopedField}" on create`, 'CWE-915', 'mass-assignment', 'high', jq),
          kind: 'http_chain',
          steps: [
            stepOf(hyp.endpoint.origin, 'c1', 'control', 'Create a record in the caller tenant', { method: 'POST', pathAndQuery: hyp.pathAndQuery, jsonBody: body(controlName, massAssignmentValue(scopedField, false)) }, hyp.ownerPersona),
            stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Create the same record with the other tenant id', { method: 'POST', pathAndQuery: hyp.pathAndQuery, jsonBody: body(probeName, expected) }, hyp.ownerPersona),
            stepOf(hyp.endpoint.origin, 'p2', 'probe', 'Read the collection as the other tenant', { method: 'GET', pathAndQuery: readPath }, hyp.otherPersona),
          ],
        },
      })
    }
  }
  for (const field of fields) {
    const lowValue = massAssignmentValue(field, false)
    const expected = massAssignmentValue(field, true, hyp.candidateValues?.[field])
    if (lowValue === null || expected === null || lowValue === expected) continue
    const write = (value: string | boolean | number): RequestParts => ({ method, pathAndQuery: hyp.pathAndQuery, jsonBody: { ...(hyp.jsonBody ?? {}), [field]: value } })
    const expectedLit = typeof expected === 'boolean' || typeof expected === 'number' ? String(expected) : jqStr(expected)
    const lowLit = typeof lowValue === 'boolean' || typeof lowValue === 'number' ? String(lowValue) : jqStr(lowValue)
    const jq = `{ controlPassed: (${is2xx('c1')} and ((.steps.c1.body | contains(${lowLit})))), ` +
      `confirmed: ((${is2xx('p2')}) and (.steps.p2.body | contains(${expectedLit})) and (((.steps.c1.body | contains(${expectedLit})) | not))), ` +
      `observed: (("${field} privileged value persisted")), expected: "privileged field must not be client-writable" }`
    out.push({
      kind: 'http_chain',
      vulnClass: 'mass_assignment',
      endpoint: hyp.endpoint.pathTemplate,
      spec: {
        ...baseFields(hyp.endpoint.origin, `Mass assignment of privileged field "${field}"`, 'CWE-915', 'mass-assignment', 'high', jq),
        kind: 'http_chain',
        steps: [
          stepOf(hyp.endpoint.origin, 'w1', 'control', `Baseline write of a low-privilege "${field}" value`, write(lowValue), hyp.ownerPersona),
          stepOf(hyp.endpoint.origin, 'c1', 'control', 'Read the record to confirm the baseline value', read, hyp.ownerPersona),
          stepOf(hyp.endpoint.origin, 'p1', 'probe', `Overpost the privileged "${field}" field`, write(expected), hyp.ownerPersona),
          stepOf(hyp.endpoint.origin, 'p2', 'probe', 'Re-read the record to observe persistence', read, hyp.ownerPersona),
        ],
      },
    })
  }
  return out
}

// ---------------------------------------------------------------------------------------------
// CSRF: state change accepted without the anti-CSRF token
// ---------------------------------------------------------------------------------------------

function synthCsrf(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'csrf_state_change')
  if (!hit) return []
  const readPath = String(hit.readPath ?? hyp.readPath ?? '')
  const bodyField = String(hit.bodyField ?? hyp.bodyField ?? '')
  const stateField = String(hit.stateField ?? hyp.stateField ?? bodyField)
  if (!readPath.startsWith('/') || !/^[A-Za-z0-9_.-]{1,64}$/.test(bodyField) || !/^[A-Za-z0-9_.-]{1,64}$/.test(stateField)) return []
  const controlValue = hit.controlValue
  const expectedValue = hit.expectedValue
  if (controlValue === undefined || expectedValue === undefined || controlValue === expectedValue) return []
  const method = (hyp.method === 'PUT' || hyp.method === 'PATCH' ? hyp.method : 'POST') as 'POST' | 'PUT' | 'PATCH'
  const stateLit = (value: unknown) => typeof value === 'boolean' || typeof value === 'number' ? String(value) : jqStr(String(value))
  const createTemplate = typeof hit.createReadTemplate === 'string' && hit.createReadTemplate.startsWith('/')
    ? hit.createReadTemplate
    : hit.create === true && typeof hyp.createReadTemplate === 'string' && hyp.createReadTemplate.startsWith('/')
      ? hyp.createReadTemplate
      : ''
  const sessionExtra = hyp.session ? { session: hyp.session } : {}
  if (createTemplate) {
    const readFor = (variable: string): RequestParts => ({
      method: 'GET',
      pathAndQuery: createTemplate.replace(/:([A-Za-z0-9_]+)/g, `{{${variable}}}`),
    })
    const aliases = /(?:amount|value|total|price|cents)/i.test(bodyField)
      ? ['amount', 'amount_cents', 'amountCents', 'value', 'cents', 'total', 'price', bodyField]
      : [bodyField]
    const body = (value: unknown, foreign: boolean): RequestParts => {
      const headers: Record<string, string> = foreign
        ? { Origin: 'https://untrusted.invalid', Referer: 'https://untrusted.invalid/' }
        : {}
      const payload: Record<string, unknown> = { ...(hyp.jsonBody ?? {}) }
      for (const alias of new Set(aliases)) payload[alias] = value
      if (hit.bodyEncoding === 'json') {
        return { method: 'POST', pathAndQuery: hyp.pathAndQuery, headers, jsonBody: payload }
      }
      return {
        method: 'POST',
        pathAndQuery: hyp.pathAndQuery,
        headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
        textBody: Object.entries(payload).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
      }
    }
    const jq = `{ controlPassed: ((${is2xx('c1')}) and (${is2xx('r1')}) and (.steps.r1.body | contains(${stateLit(controlValue)}))), ` +
      `confirmed: ((${is2xx('p1')}) and (${is2xx('p2')}) and (.steps.p2.body | contains(${stateLit(expectedValue)}))), ` +
      'observed: "tokenless cross-origin create was persisted", expected: "state change must require the anti-CSRF token" }'
    return [{
      kind: 'http_chain',
      vulnClass: 'csrf',
      endpoint: hyp.endpoint.pathTemplate,
      spec: {
        ...baseFields(hyp.endpoint.origin, 'CSRF protection missing on a create request', 'CWE-352', 'csrf', 'high', jq),
        kind: 'http_chain',
        steps: [
          stepOf(hyp.endpoint.origin, 's2', 'setup', 'Load the state page so the jar binds its anti-CSRF token', { method: 'GET', pathAndQuery: '/' }, hyp.ownerPersona, sessionExtra),
          {
            ...stepOf(hyp.endpoint.origin, 'c1', 'control', 'Create with the anti-CSRF token bound', body(controlValue, false), hyp.ownerPersona, { ...sessionExtra, csrfBind: true }),
            extract: [{ varName: 'control_id', from: 'json' as const, selector: 'id' }],
          },
          stepOf(hyp.endpoint.origin, 'r1', 'control', 'Read the control-created object', readFor('control_id'), hyp.ownerPersona, sessionExtra),
          {
            ...stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Create without the anti-CSRF token (foreign Origin)', body(expectedValue, true), hyp.ownerPersona, sessionExtra),
            extract: [{ varName: 'probe_id', from: 'json' as const, selector: 'id' }],
          },
          stepOf(hyp.endpoint.origin, 'p2', 'probe', 'Read the probe-created object', readFor('probe_id'), hyp.ownerPersona, sessionExtra),
        ],
      },
    }]
  }
  const read: RequestParts = { method: 'GET', pathAndQuery: readPath }
  const useForm = hit.bodyEncoding === 'form'
  const write = (value: unknown, foreign: boolean): RequestParts => {
    const headers: Record<string, string> = foreign
      ? { Origin: 'https://untrusted.invalid', Referer: 'https://untrusted.invalid/' }
      : {}
    const body = { ...(hyp.jsonBody ?? {}), [bodyField]: value }
    if (useForm) {
      return {
        method,
        pathAndQuery: hyp.pathAndQuery,
        headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
        textBody: Object.entries(body).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
      }
    }
    return { method, pathAndQuery: hyp.pathAndQuery, headers, jsonBody: body }
  }
  const jq = `{ controlPassed: ((${is2xx('c1')}) and (${is2xx('r1')}) and (((.steps.r1.body | contains(${stateLit(controlValue)})) or (.steps.r1.json[${jqStr(stateField)}] == ${stateLit(controlValue)})))), ` +
    `confirmed: ((${is2xx('p1')}) and (${is2xx('p2')}) and ((.steps.p2.body | contains(${stateLit(expectedValue)})) or (.steps.p2.json[${jqStr(stateField)}] == ${stateLit(expectedValue)}))), ` +
    'observed: ("state=" + ((.steps.p2.json[' + jqStr(stateField) + '] // "collection") | tostring)), expected: "state change must require the anti-CSRF token" }'
  const steps: Array<Record<string, unknown>> = [
    stepOf(hyp.endpoint.origin, 's2', 'setup', 'Load the state page so the jar binds its anti-CSRF token', read, hyp.ownerPersona, sessionExtra),
    stepOf(hyp.endpoint.origin, 'c1', 'control', 'State change with the anti-CSRF token bound', write(controlValue, false), hyp.ownerPersona, { ...sessionExtra, csrfBind: true }),
    stepOf(hyp.endpoint.origin, 'r1', 'control', 'Read the restored baseline state', read, hyp.ownerPersona, sessionExtra),
    stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Same state change without the anti-CSRF token (foreign Origin)', write(expectedValue, true), hyp.ownerPersona, sessionExtra),
    stepOf(hyp.endpoint.origin, 'p2', 'probe', 'Read the mutated state', read, hyp.ownerPersona, sessionExtra),
  ]
  return [{
    kind: 'http_chain',
    vulnClass: 'csrf',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'CSRF protection missing on a state-changing request', 'CWE-352', 'csrf', 'high', jq),
      kind: 'http_chain',
      steps,
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// Credential exposure on a read route
// ---------------------------------------------------------------------------------------------

/** Cross-actor read of a sensitive response (matrix `secret_disclosed` signal, redacted-safe). */
function synthSensitiveRead(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'secret_disclosed' && typeof a.actor === 'string')
  if (!hit || !hyp.ownerPersona) return []
  const path = typeof hit.path === 'string' && hit.path.startsWith('/') ? hit.path : hyp.pathAndQuery
  const probePersona = typeof hit.persona === 'string' && /^[a-z0-9_-]{1,32}$/.test(hit.persona) ? hit.persona : undefined
  if (!probePersona || probePersona === hyp.ownerPersona) return []
  const pattern = typeof hit.secretPattern === 'string' ? hit.secretPattern : ''
  const jq = `{ controlPassed: ((${is2xx('c1')}) and ((.steps.c1.body | length) > 2)), ` +
    `confirmed: ((${is2xx('p1')}) and (.steps.p1.body == .steps.c1.body) and ` +
    `${pattern ? `((.steps.p1.body | test(${jqStr(pattern)})) or (.steps.p1.body | contains("[redacted]")))` : '((.steps.p1.body | length) > 2)'}), ` +
    'observed: ("probe status=" + (.steps.p1.status | tostring)), expected: "sensitive data is restricted to the authorized actor" }'
  return [{
    kind: 'http_chain',
    vulnClass: 'info_disclosure',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'Cross-actor sensitive-data read', 'CWE-200', 'information-disclosure', 'medium', jq),
      kind: 'http_chain',
      steps: [
        stepOf(hyp.endpoint.origin, 'c1', 'control', 'Authorized actor reads the sensitive response', { method: 'GET', pathAndQuery: path }, hyp.ownerPersona),
        stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Lower-privileged actor reads the same response', { method: 'GET', pathAndQuery: path }, probePersona),
      ],
    },
  }]
}

function synthSecretDisclosure(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'secret_disclosed')
  if (!hit) return []
  const path = typeof hit.path === 'string' && hit.path.startsWith('/') ? hit.path : hyp.pathAndQuery
  // A same-endpoint compact toggle is not a trustworthy control (the app may ignore the query
  // name). A benign page proves the credential is not a site-wide constant while avoiding a 4xx
  // control that the replay verifier would treat as an unstable baseline.
  const controlPath = '/'
  const secretPersona = typeof hit.persona === 'string' && /^[a-z0-9_-]{1,32}$/.test(hit.persona) ? hit.persona : hyp.ownerPersona
  const field = typeof hit.field === 'string' ? hit.field : ''
  const pattern = typeof hit.pattern === 'string' && hit.pattern.length > 3
    ? hit.pattern
    : typeof hit.secretPattern === 'string' && hit.secretPattern.length > 3 ? hit.secretPattern : ''
  if (!path.startsWith('/')) return []
  const sensitiveSelector = field && /^[A-Za-z0-9_.-]{1,64}$/.test(field)
    ? `select(.key == ${jqStr(field)})`
    : 'select(.key | test("secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|password|private[_-]?key"; "i"))'
  const rawSelector = `([.steps.%s.json | .. | objects | to_entries[] | ${sensitiveSelector} | select(.value | type == "string") | select((.value | length) > 8) | select((.value | test("^[*…]|\\[redacted\\]"; "i")) | not)] | length)`
  const controlCheck = pattern
    ? `(((.steps.c1.body // "") | test(${jqStr(pattern)})) | not)`
    : `((${rawSelector.replaceAll('%s', 'c1')}) == 0)`
  const probeCheck = pattern
    ? `((.steps.p1.body // "") | test(${jqStr(pattern)}))`
    : `((${rawSelector.replaceAll('%s', 'p1')}) >= 1)`
  const jq = `{ controlPassed: ((.steps.c1.status < 500) and ${controlCheck}), ` +
    `confirmed: ((${is2xx('p1')}) and ${probeCheck}), ` +
    'observed: "unmasked credential returned to the client", expected: "secrets are never returned to clients" }'
  return [{
    kind: 'http_chain',
    vulnClass: 'info_disclosure',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'Credential exposure on a read response', 'CWE-200', 'information-disclosure', 'high', jq),
      kind: 'http_chain',
      ...(pattern ? { proofPatterns: [pattern] } : {}),
      steps: [
        stepOf(hyp.endpoint.origin, 'c1', 'control', 'Read the compact/preview (or a benign) control', { method: 'GET', pathAndQuery: controlPath }, hyp.ownerPersona),
        stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Read the endpoint that returns the credential', { method: 'GET', pathAndQuery: path }, secretPersona),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// Reflected XSS (browser chain)
// ---------------------------------------------------------------------------------------------

function synthReflectedXss(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'xss_context')
  if (!hit || !hyp.param || hyp.location !== 'query') return []
  const context = String(hit.context ?? 'html_body')
  const chars = Array.isArray(hit.unencodedChars) ? hit.unencodedChars.map(String) : []
  if (context !== 'html_body' || !chars.includes('<') || !chars.includes('"')) return []
  const controlPath = appendQuery(hyp.pathAndQuery, hyp.param.name, 'guardian')
  const payload = `<img src=x onerror="document.title='{{canary_token}}'">`
  const encodedPayload = payload.split('{{canary_token}}').map(encodeURIComponent).join('{{canary_token}}')
  const probePath = appendQuery(hyp.pathAndQuery, hyp.param.name, encodedPayload, false)
  const persona = hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}
  const jq = '{ controlPassed: (.steps.c1.status >= 200 and .steps.c1.status < 400 and (.steps.c1.title != .canaryToken) and (([(.steps.c1.domSinkTraces // [])[] | select(.containsCanary)] | length) == 0)), ' +
    'confirmed: ((.steps.p1.status >= 200 and .steps.p1.status < 400) and ((.steps.p1.title == .canaryToken) or (([(.steps.p1.domSinkTraces // [])[] | select(.containsCanary)] | length) >= 1))), ' +
    'observed: ("probe title=" + (.steps.p1.title // "" | tostring)), expected: "reflected input is inert text" }'
  return [{
    kind: 'browser_chain',
    vulnClass: 'xss_reflected',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'Reflected cross-site scripting (executed marker)', 'CWE-79', 'xss', 'high', jq),
      kind: 'browser_chain',
      steps: [
        { id: 'c1', role: 'control', description: 'Render the page with a benign parameter value', origin: hyp.endpoint.origin, ...persona, pathAndQuery: controlPath, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 300 },
        { id: 'p1', role: 'probe', description: 'Render the page with an executable marker payload', origin: hyp.endpoint.origin, ...persona, pathAndQuery: probePath, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 800 },
      ],
    },
  }]
}

// ---------------------------------------------------------------------------------------------

/** All schema-shaped candidate specs for a signal, most specific first. */
export function synthesizeEngineSpecs(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  if (result.verdict !== 'signal') return []
  try {
    if (result.anomalies.some(anomaly => anomaly.type === 'secret_disclosed')) {
      const sensitiveRead = synthSensitiveRead(hyp, result)
      if (sensitiveRead.length > 0) return sensitiveRead
      return synthSecretDisclosure(hyp, result)
    }
    switch (hyp.probeClass) {
      case 'authz_matrix': return synthAuthz(hyp, result)
      case 'sqli_boolean': return synthSqlBoolean(hyp, result)
      case 'xxe_canary': return synthXxe(hyp, result)
      case 'ssrf_canary': return synthSsrf(hyp, result)
      case 'path_traversal_benign': return synthTraversal(hyp, result)
      case 'open_redirect_differential': return synthRedirect(hyp, result)
      case 'graphql_audit': return synthGraphql(hyp, result)
      case 'mass_assignment': return synthMassAssignment(hyp, result)
      case 'xss_context': return synthReflectedXss(hyp, result)
      case 'csrf_state_change': return synthCsrf(hyp, result)
      default: return []
    }
  } catch {
    return []
  }
}

/** Stable class label for a synthesized spec (used for attribution and hide-confirmed). */
export function vulnClassOfSpec(spec: Record<string, unknown>): string {
  const cwe = typeof spec.cwe === 'string' ? spec.cwe : ''
  const kind = typeof spec.kind === 'string' ? spec.kind : ''
  if (kind === 'browser_chain') return 'xss_reflected'
  if (kind === 'sql_boolean_diff' || kind === 'sql_time_diff') return 'sqli'
  if (kind === 'cache_differential') return 'cache_poisoning'
  switch (cwe) {
    case 'CWE-639': return 'bola'
    case 'CWE-89': return 'sqli'
    case 'CWE-611': return 'xxe'
    case 'CWE-918': return 'ssrf'
    case 'CWE-22': return 'path_traversal'
    case 'CWE-601': return 'open_redirect'
    case 'CWE-915': return 'mass_assignment'
    case 'CWE-79': return 'xss_reflected'
    case 'CWE-525': return 'cache_poisoning'
    case 'CWE-352': return 'csrf'
    case 'CWE-200': return 'info_disclosure'
    default: return 'unknown'
  }
}
