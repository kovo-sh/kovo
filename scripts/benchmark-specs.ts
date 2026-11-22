/**
 * Replay-spec synthesis: turns a probe signal into a declarative spec for the Zero-LLM
 * `ReplayVerifier`. Specs are built only from what the probe observed (endpoint, param,
 * location, anomaly details), never from benchmark manifests.
 *
 * Every builder is intentionally strict: it returns null unless the anomaly carries enough
 * deterministic evidence to describe a reproducible request pair. The final schema validation
 * is the last line of defence so a malformed spec can never reach the verifier.
 */
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import type { AuthMutation } from '../src/replay-spec.ts'
import { fillPlaceholders, hasPathPlaceholder, needsCsrf, probePathFor } from './benchmark-probes.ts'
import type { Hypothesis, HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'

export interface SynthesizedSpec {
  kind: string
  spec: Record<string, unknown>
}

type Severity = 'high' | 'critical' | 'medium' | 'low'

function baseFields(
  env: ProbeEnv,
  title: string,
  cwe: string,
  category: string,
  severity: Severity,
  jq: string,
  opts: { impact?: string; remediation?: string; recheck?: string } = {},
) {
  return {
    version: 1,
    origin: env.origin,
    title,
    category,
    cwe,
    severity,
    severityRationale: 'Deterministic differential evidence was reproduced by the Zero-LLM verifier.',
    impact: opts.impact ?? 'An attacker can read or alter data outside their authorization.',
    remediation: opts.remediation ?? 'Validate and parameterize input; enforce server-side ownership checks.',
    recheckInstructions: opts.recheck ?? 'Replay the control and probe requests and compare the responses.',
    assertionsJq: jq,
  }
}

const jqStr = (v: string) => JSON.stringify(v)

/** Record why a signalled hypothesis produced no spec. Kept on the outcome so callers can debug misses. */
function noteNoSpec(o: HypothesisOutcome, kind: string) {
  const prev = typeof o.details.specSynthesis === 'string' ? `${o.details.specSynthesis}; ` : ''
  o.details.specSynthesis = `${prev}reason=no_spec:${kind}`
  if (process.env.GUARDIAN_BENCH_DEBUG === '1') {
    console.error(`[benchmark-specs] ${kind} ${o.hyp.endpoint.method} ${o.hyp.endpoint.path} -> reason=no_spec:${kind}`)
  }
}

function noteInvalidSpec(o: HypothesisOutcome, kind: string, issue: string) {
  const prev = typeof o.details.specSynthesis === 'string' ? `${o.details.specSynthesis}; ` : ''
  o.details.specSynthesis = `${prev}reason=invalid_spec:${kind}:${issue}`
  if (process.env.GUARDIAN_BENCH_DEBUG === '1') {
    console.error(`[benchmark-specs] ${kind} ${o.hyp.endpoint.method} ${o.hyp.endpoint.path} -> reason=invalid_spec:${kind}: ${issue}`)
  }
}

// ---------------------------------------------------------------------------
// Shared request construction
// ---------------------------------------------------------------------------

/** Body of sibling parameters for body-located probes (mirrors benchmark-probes siblingBody). */
function siblingBody(h: Hypothesis): Record<string, unknown> | undefined {
  if (h.location !== 'json' && h.location !== 'form' && h.location !== 'graphql_var') return undefined
  const body: Record<string, unknown> = {}
  for (const p of h.endpoint.params) {
    if (p.name === h.param?.name || p.location !== h.location || p.isCsrf) continue
    body[p.name] = 'guardian'
  }
  return body
}

function sessionFields(env: ProbeEnv, h: Hypothesis) {
  return {
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
    ...(env.caps.sessionAndCsrf && needsCsrf(h) ? { csrfBind: true } : {}),
  }
}

function personaOrUndefined(env: ProbeEnv): string | undefined {
  return env.owner
}

/** Build a replay step request for a single value injected at the observed parameter location. */
function injectedStepRequest(
  env: ProbeEnv,
  h: Hypothesis,
  opts: {
    method?: string
    persona?: string
    paramName?: string
    location?: string
    value?: unknown
    extraJsonBody?: Record<string, unknown>
    extraHeaders?: Record<string, string>
    useSession?: boolean
  } = {},
): Record<string, unknown> {
  const method = (opts.method ?? h.method) as 'GET' | 'POST' | 'PUT' | 'PATCH'
  const location = opts.location ?? h.location
  const paramName = opts.paramName ?? h.param?.name
  const value = opts.value
  let pathAndQuery = probePathFor(h)
  const headers: Record<string, string> = { ...(opts.extraHeaders ?? {}) }
  let jsonBody: Record<string, unknown> | undefined
  let textBody: string | undefined

  if (paramName && value !== undefined && location) {
    if (location === 'query') {
      pathAndQuery = appendQuery(pathAndQuery, paramName, String(value), false)
    } else if (location === 'path') {
      pathAndQuery = pathAndQuery.replaceAll('{{val}}', encodeURIComponent(String(value)))
    } else if (location === 'header') {
      headers[paramName] = String(value)
    } else if (location === 'json') {
      jsonBody = { ...(siblingBody(h) ?? {}), ...(opts.extraJsonBody ?? {}), [paramName]: value }
    } else if (location === 'form' || location === 'graphql_var') {
      const body = { ...(siblingBody(h) ?? {}), ...(opts.extraJsonBody ?? {}) }
      if (location === 'form') {
        body[paramName] = value
        const params = new URLSearchParams()
        for (const [k, v] of Object.entries(body)) params.set(k, typeof v === 'object' ? JSON.stringify(v) : String(v))
        textBody = params.toString()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
      } else {
        jsonBody = { variables: { ...body, [paramName]: value } }
      }
    }
  } else if (opts.extraJsonBody) {
    jsonBody = opts.extraJsonBody
  }

  return {
    origin: env.origin,
    method,
    pathAndQuery,
    followRedirects: false,
    ...(opts.persona ? { persona: opts.persona } : {}),
    ...(opts.useSession === false ? {} : sessionFields(env, h)),
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
    ...(jsonBody !== undefined ? { jsonBody } : {}),
    ...(textBody !== undefined ? { textBody } : {}),
  }
}

function appendQuery(pathAndQuery: string, name: string, rawValue: string, encodeValue = true): string {
  const sep = pathAndQuery.includes('?') ? '&' : '?'
  const encodedName = encodeURIComponent(name)
  const encodedValue = encodeValue ? encodeURIComponent(rawValue) : rawValue
  return `${pathAndQuery}${sep}${encodedName}=${encodedValue}`
}

function step(id: string, role: 'setup' | 'control' | 'probe', description: string, request: Record<string, unknown>) {
  return { id, role, description, request }
}

// ---------------------------------------------------------------------------
// SQL injection (boolean differential + DB error fingerprint + time differential)
// ---------------------------------------------------------------------------

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

/** SQLi with a directly observed boolean differential: replay the exact style the probe proved. */
function synthBooleanFromDifferential(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  const hit = o.anomalies.find(a => a.type === 'boolean_differential')
  const param = o.hyp.param
  if (!hit || !param || !o.hyp.location) return null
  const style = booleanStyle(String(hit.style ?? 'single_quote'))
  const body: Record<string, unknown> = {}
  for (const p of o.hyp.endpoint.params) {
    if (p.name !== param.name && p.location === o.hyp.location && !p.isCsrf) body[p.name] = 'guardian'
  }
  const spec = {
    ...baseFields(env, 'Boolean-based SQL injection differential', 'CWE-89', 'injection-input', 'high',
      '{ controlPassed: (.sqlDiff.controlPassed == true), confirmed: (.sqlDiff.passed == true), observed: ("passed=" + (.sqlDiff.passed | tostring)), expected: "boolean differential holds" }'),
    kind: 'sql_boolean_diff',
    targetOrigin: env.origin,
    method: o.hyp.method,
    pathAndQuery: probePathFor(o.hyp),
    ...(env.owner ? { persona: env.owner } : {}),
    ...sessionFields(env, o.hyp),
    ...(o.hyp.location === 'json' || o.hyp.location === 'form' ? { jsonBody: body } : {}),
    paramName: param.name,
    paramLocation: o.hyp.location,
    baselineValue: '1',
    quoteStyle: style.quoteStyle,
    ...(style.valueTemplate ? { valueTemplate: style.valueTemplate } : {}),
  }
  return { kind: 'sql_boolean_diff', spec }
}

/**
 * Error-fingerprint evidence proves the value reaches a SQL string literal, but the probe never
 * found a data-dependent baseline. A tautology baseline (`x' OR 1=1-- -`) plus probe values
 * (`x' OR k=k-- -` / `x' OR k=k+1-- -`) still produce a genuine boolean differential on any
 * relational backend (all rows vs. only rows whose key is `x`), with no knowledge of application
 * data. The verifier's randomized k triplet is what decides confirmation.
 */
function synthBooleanFromDbError(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  const hit = o.anomalies.find(a => a.type === 'db_error_fingerprint')
  const param = o.hyp.param
  if (!hit || !param || !o.hyp.location) return null
  if (o.hyp.location === 'xml' || o.hyp.location === 'graphql_var') return null
  const body: Record<string, unknown> = {}
  for (const p of o.hyp.endpoint.params) {
    if (p.name !== param.name && p.location === o.hyp.location && !p.isCsrf) body[p.name] = 'guardian'
  }
  const spec = {
    ...baseFields(env, 'SQL injection via string-literal breakout (error fingerprint)', 'CWE-89', 'injection-input', 'high',
      '{ controlPassed: (.sqlDiff.controlPassed == true), confirmed: (.sqlDiff.passed == true), observed: ("passed=" + (.sqlDiff.passed | tostring)), expected: "boolean differential holds" }',
      { impact: 'An attacker can alter SQL query semantics and read data outside the intended filter.' }),
    kind: 'sql_boolean_diff',
    targetOrigin: env.origin,
    method: o.hyp.method,
    pathAndQuery: probePathFor(o.hyp),
    ...(env.owner ? { persona: env.owner } : {}),
    ...sessionFields(env, o.hyp),
    ...(o.hyp.location === 'json' || o.hyp.location === 'form' ? { jsonBody: body } : {}),
    paramName: param.name,
    paramLocation: o.hyp.location,
    baselineValue: "x' OR 1=1-- -",
    quoteStyle: 'single' as const,
    valueTemplate: "x' OR {{sql_expr}}-- -",
  }
  return { kind: 'sql_boolean_diff', spec }
}

function synthSqlTime(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  const hit = o.anomalies.find(a => a.type === 'sql_time_differential')
  const param = o.hyp.param
  if (!hit || !param || !o.hyp.location) return null
  if (o.hyp.location === 'xml' || o.hyp.location === 'graphql_var' || o.hyp.location === 'header') return null
  const dialectRaw = String(hit.dialect ?? '')
  const dialect = (['postgres', 'mysql', 'sqlite', 'mssql'] as const).includes(dialectRaw as never)
    ? dialectRaw as 'postgres' | 'mysql' | 'sqlite' | 'mssql'
    : null
  if (!dialect) return null
  const style = booleanStyle(String(hit.style ?? 'single_quote'))
  const observedDelay = Number(hit.delayMs)
  const delayMs = Number.isFinite(observedDelay) ? Math.max(1500, Math.min(3000, Math.round(observedDelay))) : 1500
  const body: Record<string, unknown> = {}
  for (const p of o.hyp.endpoint.params) {
    if (p.name !== param.name && p.location === o.hyp.location && !p.isCsrf) body[p.name] = 'guardian'
  }
  const spec = {
    ...baseFields(env, 'Time-based blind SQL injection', 'CWE-89', 'injection-input', 'high',
      '{ controlPassed: (.sqlTimeDiff.controlPassed == true), confirmed: (.sqlTimeDiff.passed == true), observed: (("delta=" + (.sqlTimeDiff.deltaMedianMs | tostring))), expected: "non-overlapping timing delay" }',
      { impact: 'An attacker can infer arbitrary SQL predicate truth and exfiltrate data through latency.' }),
    kind: 'sql_time_diff',
    targetOrigin: env.origin,
    method: o.hyp.method,
    pathAndQuery: probePathFor(o.hyp),
    ...(env.owner ? { persona: env.owner } : {}),
    ...sessionFields(env, o.hyp),
    ...(o.hyp.location === 'json' || o.hyp.location === 'form' ? { jsonBody: body } : {}),
    paramName: param.name,
    paramLocation: o.hyp.location,
    baselineValue: '1',
    quoteStyle: style.quoteStyle,
    dialect,
    delayMs,
    ...(style.valueTemplate ? { valueTemplate: style.valueTemplate } : {}),
  }
  return { kind: 'sql_time_diff', spec }
}

// ---------------------------------------------------------------------------
// Cross-actor authorization (existing behaviour, kept generic)
// ---------------------------------------------------------------------------

function synthAuthz(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  const hit = o.anomalies.find(a => a.type === 'unauthorized_access' && a.actor === 'other_persona')
  if (!hit || !env.owner || !env.other) return null
  const id = String(hit.resourceId)
  const method = String(hit.method ?? 'GET')
  const path = hasPathPlaceholder(o.hyp.endpoint.path)
    ? fillPlaceholders(o.hyp.endpoint.path, encodeURIComponent(id))
    : `${o.hyp.endpoint.path}?${o.hyp.endpoint.params.find(p => p.location === 'query')?.name ?? 'id'}=${encodeURIComponent(id)}`
  const request = (persona: string) => ({
    origin: env.origin, method, pathAndQuery: path, persona,
    followRedirects: false,
    ...(method !== 'GET' ? { jsonBody: {} } : {}),
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
  })
  const jq = '{ controlPassed: (.steps.c1.status >= 200 and .steps.c1.status < 300), ' +
    'confirmed: (.steps.p1.status >= 200 and .steps.p1.status < 300 and ((.steps.p1.body == .steps.c1.body) or (((.steps.p1.json | keys?) // []) == ((.steps.c1.json | keys?) // []) and ((.steps.p1.body | length) > 2)))), ' +
    'observed: ("status=" + (.steps.p1.status | tostring)), expected: "non-owner denied" }'
  const spec = {
    ...baseFields(env, 'Cross-actor object access', 'CWE-639', 'broken-access-control', 'high', jq),
    kind: 'http_chain',
    steps: [
      { id: 'c1', role: 'control', description: 'Resource owner reads the object', request: request(env.owner) },
      { id: 'p1', role: 'probe', description: `Different actor reads the same object ${jqStr(id).slice(0, 40)}`, request: request(env.other) },
    ],
  }
  return { kind: 'http_chain', spec }
}

// ---------------------------------------------------------------------------
// GraphQL schema exposure
// ---------------------------------------------------------------------------

function synthGraphql(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  const types = new Set(o.anomalies.map(a => String(a.type)))
  const hasIntrospection = types.has('introspection_enabled')
  const hasAlias = types.has('alias_batching_allowed')
  const hasSuggestion = types.has('field_suggestion_leak')
  const hasCrossPersona = types.has('graphql_cross_persona_access') || types.has('graphql_nested_bola')
  if (!hasIntrospection && !hasAlias && !hasSuggestion && !hasCrossPersona) return null

  const path = probePathFor(o.hyp)
  const persona = personaOrUndefined(env)
  const gqlRequest = (query: string, actor?: string) => ({
    origin: env.origin,
    method: 'POST' as const,
    pathAndQuery: path,
    followRedirects: false,
    ...(actor ? { persona: actor } : {}),
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
    jsonBody: { query },
  })
  const gqlStep = (id: string, role: 'control' | 'probe', description: string, query: string, actor?: string) =>
    step(id, role, description, gqlRequest(query, actor))

  // Cross-persona resolver exposure is the strongest evidence; assert that the probe actor sees
  // data the owner-only control did not.
  if (hasCrossPersona && env.owner && env.other) {
    const anomaly = o.anomalies.find(a => a.type === 'graphql_cross_persona_access' || a.type === 'graphql_nested_bola')
    const field = typeof anomaly?.field === 'string' ? anomaly.field : 'me'
    const nested = Array.isArray(anomaly?.nestedPath) ? (anomaly?.nestedPath as string[]) : []
    const selection = nested.length > 0 ? `${field}{${nested.join('{')}${'}'.repeat(nested.length)}}` : field
    const query = `{${selection}}`
    const jq = '{ controlPassed: (.steps.c1.status >= 200 and .steps.c1.status < 300), ' +
      'confirmed: (.steps.p1.status >= 200 and .steps.p1.status < 300 and ((.steps.p1.json.errors // []) | length == 0) and ((.steps.p1.json.data // null) != null)), ' +
      'observed: ("probe status=" + (.steps.p1.status | tostring)), expected: "resolver data reaches a non-owner actor" }'
    const spec = {
      ...baseFields(env, 'GraphQL resolver missing object authorization', 'CWE-639', 'broken-access-control', 'high', jq,
        { impact: 'A different authenticated actor can read GraphQL resolver data they do not own.' }),
      kind: 'http_chain',
      steps: [
        gqlStep('c1', 'control', 'Owner queries the resolver', query, env.owner),
        gqlStep('p1', 'probe', 'Different actor queries the same resolver', query, env.other),
      ],
    }
    return { kind: 'http_chain', spec }
  }

  if (hasIntrospection) {
    const jq = '{ controlPassed: (.steps.c1.status >= 200 and .steps.c1.status < 300), ' +
      'confirmed: (.steps.p1.status >= 200 and .steps.p1.status < 300 and (.steps.p1.body | contains("__schema")) and (.steps.p1.body | contains("\\"types\\"")) and ((.steps.c1.body | contains("__schema")) | not)), ' +
      'observed: ("introspection bytes=" + (.steps.p1.bodyBytes | tostring)), expected: "schema hidden without authorization" }'
    const spec = {
      ...baseFields(env, 'GraphQL introspection enabled', 'CWE-200', 'information-disclosure', 'medium', jq,
        {
          impact: 'An unauthenticated caller can enumerate the full GraphQL schema, types and mutations.',
          remediation: 'Disable introspection in production or gate it behind an admin authorization check.',
          recheck: 'Send a plain type query (control) and an introspection query (probe); the probe must not return __schema.',
        }),
      kind: 'http_chain',
      steps: [
        gqlStep('c1', 'control', 'Plain type query', '{__typename}'),
        gqlStep('p1', 'probe', 'Full introspection query', '{__schema{queryType{name} types{name kind}}}'),
      ],
    }
    return { kind: 'http_chain', spec }
  }

  if (hasAlias) {
    const jq = '{ controlPassed: (.steps.c1.status >= 200 and .steps.c1.status < 300), ' +
      'confirmed: (.steps.p1.status >= 200 and .steps.p1.status < 300 and (((.steps.p1.json.data // {}) | keys | length) >= 3)), ' +
      'observed: ("aliases=" + ((((.steps.p1.json.data // {}) | keys) | length) | tostring)), expected: "alias batching rejected" }'
    const spec = {
      ...baseFields(env, 'GraphQL alias batching allowed', 'CWE-770', 'security-misconfiguration', 'medium', jq,
        { impact: 'A caller can batch unbounded aliased fields, enabling resource-exhaustion and rate-limit bypass.' }),
      kind: 'http_chain',
      steps: [
        gqlStep('c1', 'control', 'Single field query', '{__typename}'),
        gqlStep('p1', 'probe', 'Alias-batched query', '{a0:__typename a1:__typename a2:__typename a3:__typename}'),
      ],
    }
    return { kind: 'http_chain', spec }
  }

  if (hasSuggestion) {
    const jq = '{ controlPassed: (.steps.c1.status >= 200 and .steps.c1.status < 300), ' +
      'confirmed: (((.steps.p1.body // "") | tostring) | test("did you mean"; "i")), ' +
      'observed: ("probe status=" + (.steps.p1.status | tostring)), expected: "unknown fields rejected without suggestions" }'
    const spec = {
      ...baseFields(env, 'GraphQL field suggestion leakage', 'CWE-200', 'information-disclosure', 'low', jq,
        { impact: 'Field-name suggestions disclose schema members to unauthenticated callers.' }),
      kind: 'http_chain',
      steps: [
        gqlStep('c1', 'control', 'Valid field query', '{__typename}'),
        gqlStep('p1', 'probe', 'Misspelled field query', '{__typenam}'),
      ],
    }
    return { kind: 'http_chain', spec }
  }

  return null
}

// ---------------------------------------------------------------------------
// SSRF / OOB canary
// ---------------------------------------------------------------------------

function synthSsrfCanary(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  const hit = o.anomalies.find(a => a.type === 'canary_callback')
  const paramName = typeof hit?.param === 'string' ? hit.param : o.hyp.param?.name
  if (!hit || !paramName) return null
  const location = o.hyp.location ?? (hit.variant === 'header' ? 'header' : 'query')
  if (location !== 'query' && location !== 'form' && location !== 'json' && location !== 'header') return null

  const controlValue = `${env.origin}/`
  const controlRequest = injectedStepRequest(env, o.hyp, { paramName, location, value: controlValue })
  const probeRequest = injectedStepRequest(env, o.hyp, { paramName, location, value: '{{canary_url}}' })

  const jq = '{ controlPassed: ((.steps.c1.status >= 200 and .steps.c1.status < 400) and (.canary.controlTriggered == false)), ' +
    'confirmed: ((.canary.probeTriggered == true) and (.canary.controlTriggered == false)), ' +
    'observed: ("probe callback=" + (.canary.probeTriggered | tostring) + " control callback=" + (.canary.controlTriggered | tostring)), expected: "OOB callback exclusively for the probe value" }'
  const spec = {
    ...baseFields(env, 'Server-side request forgery via OOB callback', 'CWE-918', 'server-side-request-forgery', 'high', jq,
      {
        impact: 'The server fetches attacker-controlled URLs, enabling access to internal services.',
        remediation: 'Allowlist outbound destinations and block loopback/private address ranges at the fetcher.',
        recheck: 'Submit a benign same-origin URL (control) and a Guardian canary URL (probe); only the probe may call back.',
      }),
    kind: 'http_chain',
    steps: [
      step('c1', 'control', 'Fetcher is given a benign same-origin URL', controlRequest),
      step('p1', 'probe', 'Fetcher is given a Guardian canary URL', probeRequest),
    ],
  }
  return { kind: 'http_chain', spec }
}

// ---------------------------------------------------------------------------
// Auth protocol (JWT mutation / jku OOB)
// ---------------------------------------------------------------------------

function authMutationFromName(name: string): AuthMutation | null {
  switch (name) {
    case 'alg_none': return { kind: 'alg_none' }
    case 'strip_signature': return { kind: 'strip_signature' }
    case 'expired_replay': return { kind: 'expired_replay', skewSeconds: 7200 }
    case 'kid_inject': return { kind: 'kid_inject', value: "1' OR '1'='1" }
    case 'rs256_to_hs256_jwks': return { kind: 'rs256_to_hs256_jwks' }
    case 'jku_x5u_canary': return { kind: 'jku_x5u_canary', header: 'jku' }
    case 'claim_swap': return { kind: 'claim_swap', claims: { role: 'admin' } }
    default: return null
  }
}

function synthAuthProtocol(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  const jkuHit = o.anomalies.find(a => a.type === 'jwt_jku_x5u_oob_canary')
  const bypassHit = o.anomalies.find(a => a.type === 'jwt_auth_mutation_bypass')
  if (!jkuHit && !bypassHit) return null
  const jwtPersona = env.jwtPersona ?? env.owner
  if (!jwtPersona) return null

  const path = probePathFor(o.hyp)
  const method = (o.hyp.method === 'GET' ? 'GET' : o.hyp.method) as 'GET' | 'POST' | 'PUT' | 'PATCH'
  const baseRequest = (persona?: string) => ({
    origin: env.origin,
    method,
    pathAndQuery: path,
    followRedirects: false,
    ...(persona ? { persona } : {}),
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
  })

  if (jkuHit) {
    const mutation = authMutationFromName('jku_x5u_canary')
    if (!mutation) return null
    const jq = '{ controlPassed: ((.steps.c1.status >= 200 and .steps.c1.status < 300) and ((.steps.a1.status == 401) or (.steps.a1.status == 403)) and (.canaryProof.controlTriggered == false)), ' +
      'confirmed: ((.canaryProof.probeTriggered == true) and (.canaryProof.controlTriggered == false)), ' +
      'observed: ("jku callback=" + (.canaryProof.probeTriggered | tostring)), expected: "server must not fetch attacker jku URLs" }'
    const spec = {
      ...baseFields(env, 'JWT jku/x5u header triggers attacker-controlled key fetch', 'CWE-918', 'authentication', 'high', jq,
        {
          impact: 'A forged token causes the verifier to fetch an attacker-controlled JWKS URL from the server.',
          remediation: 'Pin trusted JWKS URLs and never dereference token-supplied jku/x5u headers.',
          recheck: 'Send an unauthenticated request (setup), a valid persona token (control) and a jku-mutated token (probe); only the probe may call back.',
        }),
      kind: 'auth_protocol_proof',
      protocol: 'jwt' as const,
      steps: [
        step('a1', 'setup', 'Anonymous request is rejected', baseRequest()),
        step('c1', 'control', 'Valid persona token is accepted', baseRequest(jwtPersona)),
        step('p1', 'probe', 'Token carries a Guardian canary jku URL', {
          ...baseRequest(jwtPersona),
          authMutation: mutation,
        }),
      ],
    }
    return { kind: 'auth_protocol_proof', spec }
  }

  const mutation = authMutationFromName(String(bypassHit?.mutation ?? ''))
  if (!mutation) return null
  const jq = '{ controlPassed: ((.steps.c1.status >= 200 and .steps.c1.status < 300) and ((.steps.a1.status == 401) or (.steps.a1.status == 403))), ' +
    'confirmed: (.steps.p1.status >= 200 and .steps.p1.status < 300), ' +
    'observed: ("mutated-token status=" + (.steps.p1.status | tostring)), expected: "forged token rejected" }'
  const spec = {
    ...baseFields(env, 'JWT signature validation bypass', 'CWE-347', 'authentication', 'critical', jq,
      {
        impact: 'An attacker can forge arbitrary identity claims and be accepted as another user.',
        remediation: 'Reject alg=none, require a non-empty signature and pin the accepted algorithm and key source.',
        recheck: 'Send an anonymous request, a valid token and the mutated token; only control/probe may be accepted.',
      }),
    kind: 'auth_protocol_proof',
    protocol: 'jwt' as const,
    steps: [
      step('a1', 'setup', 'Anonymous request is rejected', baseRequest()),
      step('c1', 'control', 'Valid persona token is accepted', baseRequest(jwtPersona)),
      step('p1', 'probe', `Forged token (${String(bypassHit?.mutation ?? 'mutation')}) is rejected`, {
        ...baseRequest(jwtPersona),
        authMutation: mutation,
      }),
    ],
  }
  return { kind: 'auth_protocol_proof', spec }
}

// ---------------------------------------------------------------------------
// Mass assignment
// ---------------------------------------------------------------------------

function massAssignmentValue(field: string, privileged: boolean): string | boolean {
  if (/^(?:is|has|verified|admin|emailVerified|enabled|active|superuser|staff)/i.test(field)) return privileged
  if (privileged) {
    if (/role|admin|permission|privilege|scope/i.test(field)) return 'admin'
    if (/plan|tier/i.test(field)) return 'enterprise'
    if (/org|tenant|team|group/i.test(field)) return '1'
    return 'guardian-privileged'
  }
  if (/role|permission|privilege|scope/i.test(field)) return 'user'
  if (/plan|tier/i.test(field)) return 'free'
  if (/org|tenant|team|group/i.test(field)) return '0'
  return 'guardian-low'
}

/**
 * Mass assignment is proven as a *transition*: write a low-privilege value for the observed
 * privileged field (control), read it back, then overpost the privileged value (probe) and read
 * again. This stays valid even when the account is already privileged before the replay, which
 * is exactly what happens when an earlier authz probe legitimately promotes the test user.
 */
function synthMassAssignment(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  const hit = o.anomalies.find(a => a.type === 'mass_assignment')
  if (!hit || !env.owner) return null
  const field = String(hit.field ?? '')
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(field)) return null
  const lowValue = massAssignmentValue(field, false)
  const expected = massAssignmentValue(field, true)
  if (lowValue === expected) return null
  const method = (o.hyp.method === 'PUT' ? 'PUT' : o.hyp.method === 'PATCH' ? 'PATCH' : 'POST') as 'POST' | 'PUT' | 'PATCH'
  const path = probePathFor(o.hyp)
  const readRequest = {
    origin: env.origin, method: 'GET' as const, pathAndQuery: path, persona: env.owner, followRedirects: false,
    ...sessionFields(env, o.hyp),
  }
  const writeRequest = (value: string | boolean) => ({
    origin: env.origin, method, pathAndQuery: path, persona: env.owner, followRedirects: false,
    ...sessionFields(env, o.hyp),
    jsonBody: { [field]: value },
  })
  const fieldLit = jqStr(field)
  const expectedLit = typeof expected === 'boolean' ? String(expected) : jqStr(expected)
  const lowLit = typeof lowValue === 'boolean' ? String(lowValue) : jqStr(lowValue)
  const jq = `{ controlPassed: ((.steps.c1.status >= 200 and .steps.c1.status < 300) and ((.steps.c1.json | type) == "object") and (.steps.c1.json[${fieldLit}] == ${lowLit})), ` +
    `confirmed: ((.steps.p2.status >= 200 and .steps.p2.status < 300) and ((.steps.p2.json | type) == "object") and (.steps.p2.json[${fieldLit}] == ${expectedLit})), ` +
    `observed: (("${field}=" + ((.steps.p2.json[${fieldLit}]) | tostring))), expected: "privileged field must not be writable" }`
  const spec = {
    ...baseFields(env, 'Mass assignment of a privileged profile field', 'CWE-915', 'mass-assignment', 'high', jq,
      {
        impact: `A normal user can set the privileged "${field}" field on their own profile, moving it from ${lowLit} to ${expectedLit}.`,
        remediation: 'Bind writes to an explicit allowlist of user-editable fields; never merge arbitrary request keys.',
        recheck: `Write a low-privilege value to "${field}", read it back, then overpost ${expectedLit} and re-read; the privileged value must be rejected.`,
      }),
    kind: 'http_chain',
    steps: [
      step('w1', 'control', `Baseline write of a low-privilege "${field}" value`, writeRequest(lowValue)),
      step('c1', 'control', 'Read the profile to confirm the baseline value', readRequest),
      step('p1', 'probe', `Overpost the privileged "${field}" field`, writeRequest(expected)),
      step('p2', 'probe', 'Re-read the profile to observe persistence', readRequest),
    ],
  }
  return { kind: 'http_chain', spec }
}

// ---------------------------------------------------------------------------
// Cache poisoning / deception
// ---------------------------------------------------------------------------

function synthCache(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  const poison = o.anomalies.find(a => a.type === 'cache_poisoning')
  const deception = o.anomalies.find(a => a.type === 'web_cache_deception')
  if (!poison && !deception) return null
  const path = probePathFor(o.hyp)
  const marker = 'guardian-cache-probe'

  if (poison) {
    const headerName = typeof poison.header === 'string' ? poison.header : ''
    if (!/^[A-Za-z0-9-]{1,64}$/.test(headerName) || /^(?:authorization|cookie|host)$/i.test(headerName)) return null
    const jq = '{ controlPassed: (.cacheProof.cacheHitObserved == true), ' +
      `confirmed: ((.cacheProof.cacheHitObserved == true) and (.cacheProof.poisonPersistedToVictim == true) and (.verify.body | contains(${jqStr(marker)}))), ` +
      'observed: ("age=" + ((.cacheProof.age // 0) | tostring)), expected: "poisoned response served from cache to a clean client" }'
    const spec = {
      ...baseFields(env, 'Web cache poisoning via unkeyed header', 'CWE-525', 'cache-poisoning', 'high', jq,
        {
          impact: 'An attacker can persist content into a shared cache and serve it to other users.',
          remediation: 'Include security-relevant headers in the cache key or strip them at the edge.',
          recheck: 'Prime the cache with a marker header (probe) and fetch the same URL cleanly (verify).',
        }),
      kind: 'cache_differential',
      targetOrigin: env.origin,
      mode: 'poison' as const,
      method: 'GET' as const,
      controlPath: appendQuery(path, '_gcb', '{{control_gcb}}', false),
      probePath: appendQuery(path, '_gcb', '{{probe_gcb}}', false),
      poisonHeaders: { [headerName]: marker },
      ...(env.owner ? { poisonPersona: env.owner } : {}),
    }
    return { kind: 'cache_differential', spec }
  }

  if (deception) {
    const observedUrl = typeof deception.deceptionUrl === 'string' ? deception.deceptionUrl : ''
    let deceptionPath = path
    try {
      const parsed = new URL(observedUrl, 'http://guardian.invalid')
      deceptionPath = parsed.pathname
    } catch { /* keep original path */ }
    const jq = '{ controlPassed: (.cacheProof.cacheHitObserved == true), ' +
      'confirmed: ((.cacheProof.cacheHitObserved == true) and (.cacheProof.poisonPersistedToVictim == true) and (.steps.verify.status == 200) and (.steps.verify.body != .steps.control.body)), ' +
      'observed: ("verify status=" + (.steps.verify.status | tostring)), expected: "private response not cacheable by an anonymous client" }'
    const spec = {
      ...baseFields(env, 'Web cache deception of a private page', 'CWE-525', 'cache-deception', 'high', jq,
        {
          impact: 'A private authenticated response can be cached under a static-looking URL and read by anonymous users.',
          remediation: 'Never cache authenticated responses; normalize static-looking suffixes before routing.',
        }),
      kind: 'cache_differential',
      targetOrigin: env.origin,
      mode: 'deception' as const,
      method: 'GET' as const,
      controlPath: appendQuery(path, '_gcb', '{{control_gcb}}', false),
      probePath: appendQuery(deceptionPath, '_gcb', '{{probe_gcb}}', false),
      verifyPath: appendQuery(deceptionPath, '_gcb', '{{probe_gcb}}', false),
      ...(env.owner ? { poisonPersona: env.owner } : {}),
    }
    return { kind: 'cache_differential', spec }
  }

  return null
}

// ---------------------------------------------------------------------------
// Workflow invariants (numeric boundary acceptance)
// ---------------------------------------------------------------------------

function synthWorkflow(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  const hit = o.anomalies.find(a => a.type === 'workflow_quantity_invariant')
  if (!hit) return null
  const field = String(hit.field ?? '')
  const value = Number(hit.value)
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(field) || !Number.isFinite(value)) return null
  const method = (o.hyp.method === 'PUT' ? 'PUT' : o.hyp.method === 'PATCH' ? 'PATCH' : 'POST') as 'POST' | 'PUT' | 'PATCH'
  const path = probePathFor(o.hyp)
  const request = (fieldValue: number) => ({
    origin: env.origin, method, pathAndQuery: path, followRedirects: false,
    ...(env.owner ? { persona: env.owner } : {}),
    ...sessionFields(env, o.hyp),
    jsonBody: { [field]: fieldValue },
  })
  const fieldLit = jqStr(field)
  const jq = `{ controlPassed: (.steps.c1.status >= 200 and .steps.c1.status < 300), ` +
    `confirmed: ((.steps.p1.status >= 200 and .steps.p1.status < 300) and (.steps.p1.json[${fieldLit}] == ${value})), ` +
    `observed: (("${field}=" + ((.steps.p1.json[${fieldLit}]) | tostring))), expected: "invalid quantity must be rejected" }`
  const spec = {
    ...baseFields(env, 'Business workflow quantity invariant bypass', 'CWE-840', 'business-logic', 'medium', jq,
      {
        impact: 'Invalid quantities are accepted, allowing price or inventory manipulation.',
        remediation: 'Validate quantity bounds server-side against the business invariant.',
      }),
    kind: 'http_chain',
    steps: [
      step('c1', 'control', 'Valid quantity is accepted', request(1)),
      step('p1', 'probe', `Boundary quantity ${value} is accepted`, request(value)),
    ],
  }
  return { kind: 'http_chain', spec }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

function buildForProbeClass(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  switch (o.hyp.probeClass) {
    case 'sqli_boolean':
      return synthBooleanFromDifferential(o, env) ?? synthBooleanFromDbError(o, env)
    case 'sqli_time_diff':
      return synthSqlTime(o, env)
    case 'authz_matrix':
      return synthAuthz(o, env)
    case 'graphql_audit':
      return synthGraphql(o, env)
    case 'ssrf_canary':
      return synthSsrfCanary(o, env)
    case 'auth_protocol_audit':
      return synthAuthProtocol(o, env)
    case 'mass_assignment':
      return synthMassAssignment(o, env)
    case 'cache_poison_deception':
      return synthCache(o, env)
    case 'workflow_invariant':
      return synthWorkflow(o, env)
    case 'path_traversal_benign':
      // A normalization differential alone is not proof of a file read outside the jail.
      return null
    default:
      return null
  }
}

export function synthesizeSpec(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  if (o.verdict !== 'signal') return null
  const built = buildForProbeClass(o, env)
  if (!built) {
    noteNoSpec(o, o.hyp.probeClass)
    return null
  }
  const parsed = declarativeReplaySpecSchema.safeParse(built.spec)
  if (!parsed.success) {
    noteInvalidSpec(o, built.kind, parsed.error.issues[0]?.message ?? 'schema mismatch')
    return null
  }
  return { kind: built.kind, spec: parsed.data as unknown as Record<string, unknown> }
}
