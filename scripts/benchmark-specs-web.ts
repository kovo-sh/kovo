/**
 * Spec synthesis for browser/web classes: GraphQL exposure, workflow invariants, stored
 * (second-order) XSS and DOM XSS. Builders only use endpoints, parameters and anomaly
 * observations from the probe; nothing is derived from a benchmark manifest.
 */
import { randomBytes } from 'node:crypto'
import { appendQuery, baseFields, is2xx, jqStr, sessionFields, stepOf } from './benchmark-specs-common.ts'
import type { RequestParts, SynthesizedSpec } from './benchmark-specs-common.ts'
import { fillPlaceholders, hasPathPlaceholder, probePathFor } from './benchmark-probes.ts'
import type { HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'

// ---------------------------------------------------------------------------
// GraphQL schema exposure / resolver authorization
// ---------------------------------------------------------------------------

export function synthGraphql(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const types = new Set(o.anomalies.map(a => String(a.type)))
  const hasIntrospection = types.has('introspection_enabled')
  const hasAlias = types.has('alias_batching_allowed')
  const hasSuggestion = types.has('field_suggestion_leak')
  const hasCrossPersona = types.has('graphql_cross_persona_access') || types.has('graphql_nested_bola')
  if (!hasIntrospection && !hasAlias && !hasSuggestion && !hasCrossPersona) return []

  const path = probePathFor(o.hyp)
  const gqlStep = (id: string, role: 'control' | 'probe', description: string, query: string, actor?: string) =>
    stepOf(env, id, role, description, { method: 'POST', pathAndQuery: path, jsonBody: { query } }, actor)

  // Cross-persona resolver exposure is the strongest evidence.
  if (hasCrossPersona && env.owner && env.other) {
    const anomaly = o.anomalies.find(a => a.type === 'graphql_cross_persona_access' || a.type === 'graphql_nested_bola')
    const field = typeof anomaly?.field === 'string' ? anomaly.field : 'me'
    const nested = Array.isArray(anomaly?.nestedPath) ? (anomaly?.nestedPath as string[]) : []
    const selection = nested.length > 0 ? `${field}{${nested.join('{')}${'}'.repeat(nested.length)}}` : field
    const query = `{${selection}}`
    const jq = `{ controlPassed: ${is2xx('c1')}, ` +
      `confirmed: (${is2xx('p1')} and (((.steps.p1.json.errors // []) | length) == 0) and ((.steps.p1.json.data // null) != null)), ` +
      'observed: ("probe status=" + (.steps.p1.status | tostring)), expected: "resolver data reaches a non-owner actor" }'
    return [{
      kind: 'http_chain',
      spec: {
        ...baseFields(env, 'GraphQL resolver missing object authorization', 'CWE-639', 'broken-access-control', 'high', jq),
        kind: 'http_chain',
        steps: [
          gqlStep('c1', 'control', 'Owner queries the resolver', query, env.owner),
          gqlStep('p1', 'probe', 'Different actor queries the same resolver', query, env.other),
        ],
      },
    }]
  }

  if (hasIntrospection) {
    const jq = `{ controlPassed: ${is2xx('c1')}, ` +
      'confirmed: ((' + is2xx('p1') + ') and (.steps.p1.body | contains("__schema")) and (.steps.p1.body | contains("\\"types\\"")) and ((.steps.c1.body | contains("__schema")) | not)), ' +
      'observed: ("introspection bytes=" + (.steps.p1.body | length | tostring)), expected: "schema hidden without authorization" }'
    return [{
      kind: 'http_chain',
      spec: {
        ...baseFields(env, 'GraphQL introspection enabled', 'CWE-200', 'information-disclosure', 'medium', jq),
        kind: 'http_chain',
        steps: [
          gqlStep('c1', 'control', 'Plain type query', '{__typename}'),
          gqlStep('p1', 'probe', 'Full introspection query', '{__schema{queryType{name} types{name kind}}}'),
        ],
      },
    }]
  }

  if (hasAlias) {
    const jq = `{ controlPassed: ${is2xx('c1')}, ` +
      'confirmed: ((' + is2xx('p1') + ') and (((.steps.p1.json.data // {}) | keys | length) >= 3)), ' +
      'observed: ("aliases=" + (((.steps.p1.json.data // {}) | keys | length) | tostring)), expected: "alias batching rejected" }'
    return [{
      kind: 'http_chain',
      spec: {
        ...baseFields(env, 'GraphQL alias batching allowed', 'CWE-770', 'security-misconfiguration', 'medium', jq),
        kind: 'http_chain',
        steps: [
          gqlStep('c1', 'control', 'Single field query', '{__typename}'),
          gqlStep('p1', 'probe', 'Alias-batched query', '{a0:__typename a1:__typename a2:__typename a3:__typename}'),
        ],
      },
    }]
  }

  if (hasSuggestion) {
    const jq = `{ controlPassed: ${is2xx('c1')}, ` +
      'confirmed: (((.steps.p1.body // "") | tostring) | test("did you mean"; "i")), ' +
      'observed: ("probe status=" + (.steps.p1.status | tostring)), expected: "unknown fields rejected without suggestions" }'
    return [{
      kind: 'http_chain',
      spec: {
        ...baseFields(env, 'GraphQL field suggestion leakage', 'CWE-200', 'information-disclosure', 'low', jq),
        kind: 'http_chain',
        steps: [
          gqlStep('c1', 'control', 'Valid field query', '{__typename}'),
          gqlStep('p1', 'probe', 'Misspelled field query', '{__typenam}'),
        ],
      },
    }]
  }

  return []
}

// ---------------------------------------------------------------------------
// Business workflow invariant (invalid quantity accepted)
// ---------------------------------------------------------------------------

export function synthWorkflow(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'workflow_quantity_invariant')
  if (!hit) return []
  const field = String(hit.field ?? '')
  const value = Number(hit.value)
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(field) || !Number.isFinite(value)) return []
  const method = (o.hyp.method === 'PUT' ? 'PUT' : o.hyp.method === 'PATCH' ? 'PATCH' : 'POST') as 'POST' | 'PUT' | 'PATCH'
  const path = probePathFor(o.hyp)
  const request = (fieldValue: number): RequestParts => ({ method, pathAndQuery: path, jsonBody: { [field]: fieldValue } })
  const fieldLit = jqStr(field)
  const jq = `{ controlPassed: ${is2xx('c1')}, ` +
    `confirmed: ((${is2xx('p1')} and (.steps.p1.json[${fieldLit}] == ${value}))), ` +
    `observed: (("${field}=" + ((.steps.p1.json[${fieldLit}]) | tostring))), expected: "invalid quantity must be rejected" }`
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env, 'Business workflow quantity invariant bypass', 'CWE-840', 'business-logic', 'medium', jq),
      kind: 'http_chain',
      steps: [
        stepOf(env, 'c1', 'control', 'Valid quantity is accepted', request(1), env.owner),
        stepOf(env, 'p1', 'probe', `Boundary quantity ${value} is accepted`, request(value), env.owner),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------
// Second-order (stored) XSS: plant through the write route, read downstream
// ---------------------------------------------------------------------------

function plantRequest(o: HypothesisOutcome, env: ProbeEnv, anom: Record<string, unknown>, value: string): RequestParts | null {
  const location = String(anom.plantLocation ?? '')
  const param = String(anom.plantParam ?? '')
  const rawPath = String(anom.plantPath ?? o.hyp.endpoint.path)
  const path = hasPathPlaceholder(rawPath) ? fillPlaceholders(rawPath, '1') : rawPath
  const method = o.hyp.method === 'GET' ? 'POST' : o.hyp.method
  const siblings: Record<string, unknown> = {}
  for (const p of o.hyp.endpoint.params) {
    if (p.name !== param && p.location === location && !p.isCsrf) siblings[p.name] = 'guardian'
  }
  switch (location) {
    case 'query': return { method, pathAndQuery: `${path}?${encodeURIComponent(param)}=${encodeURIComponent(value)}` }
    case 'path': return { method, pathAndQuery: path.replaceAll('{{val}}', encodeURIComponent(value)) }
    case 'header': return { method, pathAndQuery: path, headers: { [param]: value } }
    case 'json': return { method, pathAndQuery: path, jsonBody: { ...siblings, [param]: value } }
    case 'form': {
      const all = { ...siblings, [param]: value }
      return {
        method, pathAndQuery: path,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        textBody: Object.entries(all).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
      }
    }
    case 'xml': {
      const tpl = o.ctx?.xmlTemplate ?? `<root><${param}>{{val}}</${param}></root>`
      return { method: 'POST', pathAndQuery: path, headers: { 'Content-Type': 'application/xml' }, textBody: tpl.replaceAll('{{val}}', value) }
    }
    case 'graphql_var': {
      const query = o.ctx?.graphqlQuery
      if (!query) return null
      return { method: 'POST', pathAndQuery: path, jsonBody: { query, variables: { ...siblings, [param]: value } } }
    }
    default: return null
  }
}

/** Marker plus only the character classes the probe observed as unencoded in the read response. */
function storedXssPayload(anom: Record<string, unknown>): string {
  const marker = `gxss${randomBytes(5).toString('hex')}`
  const chars = Array.isArray(anom.unencodedChars) ? anom.unencodedChars.map(String) : []
  let suffix = ''
  if (chars.includes('<') || chars.includes('>')) suffix += '<b>'
  if (chars.includes('"')) suffix += '"'
  if (chars.includes("'")) suffix += "'"
  if (!suffix) suffix = '<b>'
  return `${marker}${suffix}`
}

export function synthSecondOrderXss(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'second_order_xss')
  if (!hit) return []
  const readPath = String(hit.readPath ?? '')
  if (!readPath.startsWith('/')) return []
  const payload = storedXssPayload(hit)
  const plant = plantRequest(o, env, hit, payload)
  if (!plant) return []
  const jq = `{ controlPassed: (${is2xx('c1')} and ((.steps.c1.body | contains(${jqStr(payload)})) | not)), ` +
    `confirmed: ((${is2xx('p2')} and (.steps.p2.body | contains(${jqStr(payload)})) and ((.steps.p1.status < 400)))), ` +
    'observed: ("stored marker on " + (.steps.p2.status | tostring)), expected: "stored input is HTML-encoded on read" }'
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env, 'Stored (second-order) cross-site scripting', 'CWE-79', 'xss', 'high', jq),
      kind: 'http_chain',
      steps: [
        stepOf(env, 'c1', 'control', 'Read the downstream route before planting', { method: 'GET', pathAndQuery: readPath }, env.owner),
        stepOf(env, 'p1', 'probe', 'Plant the marker through the write route', plant, env.owner),
        stepOf(env, 'p2', 'probe', 'Re-read the downstream route', { method: 'GET', pathAndQuery: readPath }, env.owner),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------
// DOM XSS: replay the interactive sequence in the scoped browser
// ---------------------------------------------------------------------------

interface BrowserAction { type: 'fill' | 'click'; selector: string }

function parseActions(anom: Record<string, unknown>): BrowserAction[] {
  const raw = Array.isArray(anom.actions) ? anom.actions.map(String) : []
  const out: BrowserAction[] = []
  for (const entry of raw) {
    const m = /^(fill|click)\s+(.+)$/i.exec(entry.trim())
    if (!m) continue
    const selector = m[2].trim()
    if (!selector || /[<>{};`\\]|javascript:/i.test(selector)) continue
    out.push({ type: m[1].toLowerCase() as 'fill' | 'click', selector })
  }
  return out
}

export function synthDomXss(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'dom_xss_sink')
  if (!hit || hit.canaryTriggered !== true) return []
  const path = String(hit.path ?? o.hyp.endpoint.path)
  if (!path.startsWith('/')) return []
  const actions = parseActions(hit)
  const fills = actions.filter(a => a.type === 'fill').slice(0, 2)
  const clicks = actions.filter(a => a.type === 'click').slice(0, 2)
  if (fills.length === 0 || clicks.length === 0) return []

  const stepBase = {
    origin: env.origin,
    ...(env.owner ? { persona: env.owner } : {}),
    ...sessionFields(env, o.hyp),
    checkKind: 'dom_xss' as const,
    enableSinkHook: true,
  }
  const stepIds = ['p1']
  let n = 2
  for (let i = 0; i < fills.length; i += 1) stepIds.push(`p${n++}`)
  for (let i = 0; i < clicks.length; i += 1) stepIds.push(`p${n++}`)
  stepIds.push(`p${n}`)
  const tracesExpr = `[(${stepIds.map(id => `(.steps.${id}.domSinkTraces // [])`).join(' + ')})[] | select(.containsCanary)]`
  const jq = '{ controlPassed: (.steps.c1.status == 200 and (([(.steps.c1.domSinkTraces // [])[] | select(.containsCanary)] | length) == 0)), ' +
    `confirmed: ((${tracesExpr} | length) >= 1), ` +
    `observed: ("probe sink hits=" + (${tracesExpr} | length | tostring)), expected: "canary never reaches an executable DOM sink" }`

  const steps: Array<Record<string, unknown>> = [
    { id: 'c1', role: 'control', description: 'Render the page without interaction', ...stepBase, pathAndQuery: path, action: 'navigate', waitAfterLoadMs: 300 },
    { id: 'p1', role: 'probe', description: 'Render the page with the sink hook armed', ...stepBase, pathAndQuery: path, action: 'navigate', waitAfterLoadMs: 300 },
  ]
  n = 2
  for (const fill of fills) {
    steps.push({
      id: `p${n}`, role: 'probe', description: `Fill ${fill.selector.slice(0, 80)} with the canary`,
      ...stepBase, action: 'fill', selector: fill.selector, value: '{{canary_token}}<b>', waitAfterLoadMs: 100,
    })
    n += 1
  }
  for (const click of clicks) {
    steps.push({
      id: `p${n}`, role: 'probe', description: `Click ${click.selector.slice(0, 80)}`,
      ...stepBase, action: 'click', selector: click.selector, waitAfterLoadMs: 300,
    })
    n += 1
  }
  steps.push({
    id: `p${n}`, role: 'probe', description: 'Snapshot DOM sinks after interaction',
    ...stepBase, action: 'dom_xss_sink_hook', waitAfterLoadMs: 300,
  })

  return [{
    kind: 'browser_chain',
    spec: {
      ...baseFields(env, 'DOM-based cross-site scripting via interactive sink', 'CWE-79', 'xss', 'high', jq),
      kind: 'browser_chain',
      steps,
    },
  }]
}

// ---------------------------------------------------------------------------
// Reflected XSS: replay the unencoded reflection in the scoped browser
// ---------------------------------------------------------------------------

/**
 * The surface probe already proved the marker is reflected into a renderable context with dangerous
 * characters unencoded. Confirmation replays an executable payload whose only visible effect is the
 * verifier-minted canary token becoming the document title; encoded reflections leave the title alone.
 */
export function synthReflectedXss(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'xss_context')
  if (!hit || !o.hyp.param || o.hyp.location !== 'query') return []
  const context = String(hit.context ?? 'html_body')
  const chars = Array.isArray(hit.unencodedChars) ? hit.unencodedChars.map(String) : []
  // Only markup contexts where an injected tag actually parses; attribute/JS contexts need a
  // different escape and are deliberately not synthesized from a plain tag payload.
  if (context !== 'html_body' || !chars.includes('<') || !chars.includes('"')) return []
  const basePath = o.hyp.endpoint.path
  if (!basePath.startsWith('/')) return []
  const controlPath = appendQuery(basePath, o.hyp.param.name, 'guardian')
  const payload = `<img src=x onerror="document.title='{{canary_token}}'">`
  const probePath = appendQuery(basePath, o.hyp.param.name, payload)
  const params = { origin: env.origin, ...(env.owner ? { persona: env.owner } : {}), ...sessionFields(env, o.hyp) }
  const jq = '{ controlPassed: (.steps.c1.status >= 200 and .steps.c1.status < 400 and (.steps.c1.title != .canaryToken) and (([(.steps.c1.domSinkTraces // [])[] | select(.containsCanary)] | length) == 0)), ' +
    'confirmed: ((.steps.p1.status >= 200 and .steps.p1.status < 400) and ((.steps.p1.title == .canaryToken) or (([(.steps.p1.domSinkTraces // [])[] | select(.containsCanary)] | length) >= 1))), ' +
    'observed: ("probe title=" + (.steps.p1.title // "" | tostring)), expected: "reflected input is inert text" }'
  return [{
    kind: 'browser_chain',
    spec: {
      ...baseFields(env, 'Reflected cross-site scripting (executed marker)', 'CWE-79', 'xss', 'high', jq),
      kind: 'browser_chain',
      steps: [
        { id: 'c1', role: 'control', description: 'Render the page with a benign parameter value', ...params, pathAndQuery: controlPath, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 300 },
        { id: 'p1', role: 'probe', description: 'Render the page with an executable marker payload', ...params, pathAndQuery: probePath, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 800 },
      ],
    },
  }]
}
