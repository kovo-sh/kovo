/**
 * Spec synthesis for browser/web classes: GraphQL exposure, workflow invariants, stored
 * (second-order) XSS and DOM XSS. Builders only use endpoints, parameters and anomaly
 * observations from the probe; nothing is derived from a benchmark manifest.
 */
import { randomBytes } from 'node:crypto'
import { appendQuery, baseFields, is2xx, jqStr, sessionFields, stepOf } from './benchmark-specs-common.ts'
import type { RequestParts, SynthesizedSpec } from './benchmark-specs-common.ts'
import { browserSinkEnvelopeFromSteps } from '../src/server/floor-recipes.ts'
import { fillPlaceholders, hasPathPlaceholder, probePathFor, siblingValue } from './benchmark-probes.ts'
import type { HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'

// ---------------------------------------------------------------------------
// GraphQL schema exposure / resolver authorization
// ---------------------------------------------------------------------------

export function synthGraphql(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const types = new Set(o.anomalies.map(a => String(a.type)))
  const hasIntrospection = types.has('introspection_enabled')
  const hasAlias = types.has('alias_batching_allowed')
  const hasSuggestion = types.has('field_suggestion_leak')
  const hasCrossPersona = types.has('graphql_cross_persona_access') || types.has('graphql_nested_bola') || types.has('graphql_bola_differential')
  if (!hasIntrospection && !hasAlias && !hasSuggestion && !hasCrossPersona) return []

  const path = probePathFor(o.hyp)
  const gqlStep = (id: string, role: 'control' | 'probe', description: string, query: string, actor?: string) =>
    stepOf(env, id, role, description, { method: 'POST', pathAndQuery: path, jsonBody: { query } }, actor)

  // Cross-persona resolver exposure is the strongest evidence. The probe records the exact operation
  // and variables it used, so the replay reproduces the same object (id arg) and nested selection.
  if (hasCrossPersona && env.owner && env.other) {
    const anomaly = o.anomalies.find(a => a.type === 'graphql_cross_persona_access' || a.type === 'graphql_nested_bola' || a.type === 'graphql_bola_differential')
    const field = typeof anomaly?.field === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(anomaly.field) ? anomaly.field : null
    const nested = Array.isArray(anomaly?.nestedPath)
      ? (anomaly.nestedPath as unknown[]).filter((x): x is string => typeof x === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(x))
      : []
    // The probe may not have introspection available; it records the nested operation it built from
    // field-suggestion/error differentials instead. Accept either spelling, but never invent a query.
    const recordedQueryRaw = typeof anomaly?.query === 'string'
      ? anomaly.query
      : typeof anomaly?.nestedQuery === 'string' ? anomaly.nestedQuery
        : typeof anomaly?.operation === 'string' ? anomaly.operation : null
    const recordedQuery = recordedQueryRaw && recordedQueryRaw.length <= 4000 &&
      /^\s*(?:[{(]|query\b|mutation\b|subscription\b|fragment\b)/.test(recordedQueryRaw) ? recordedQueryRaw : null
    const variables = anomaly?.variables && typeof anomaly.variables === 'object' && !Array.isArray(anomaly.variables)
      ? anomaly.variables as Record<string, unknown> : {}
    if (!recordedQuery) return []
    if (anomaly?.sameRoot === false) return []
    const dataPath = field ? ['data', field, ...nested].map(p => `[${jqStr(p)}]`).join('') : '.data'
    const nestedLen = (id: string) => `((.steps.${id}.json${dataPath} // []) | length)`
    const errorsClean = (id: string) => `(((.steps.${id}.json.errors // []) | length) == 0)`
    const jq = `{ controlPassed: (${is2xx('c1')} and ${errorsClean('c1')} and (${nestedLen('c1')} >= 1)), ` +
      `confirmed: (${is2xx('p1')} and ${errorsClean('p1')} and (${nestedLen('p1')} >= 1) and (.steps.p1.json${dataPath} == .steps.c1.json${dataPath})), ` +
      `observed: ("nested records=" + (${nestedLen('p1')} | tostring)), expected: "nested owned data reaches only its owner" }`
    const step = (id: string, role: 'control' | 'probe', description: string, actor: string) =>
      stepOf(env, id, role, description, {
        method: 'POST', pathAndQuery: path, jsonBody: { query: recordedQuery, ...(Object.keys(variables).length > 0 ? { variables } : {}) },
      }, actor)
    return [{
      kind: 'http_chain',
      spec: {
        ...baseFields(env, 'GraphQL resolver missing object authorization', 'CWE-639', 'broken-access-control', 'high', jq),
        kind: 'http_chain',
        steps: [
          step('c1', 'control', 'Owner queries the resolver', env.owner),
          step('p1', 'probe', 'Different actor queries the same resolver', env.other),
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

/** Workflow step-skip: a later transition is accepted for a fresh object whose prerequisite flag is false. */
export function synthWorkflowStepSkip(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'workflow_step_skip')
  if (!hit) return []
  const safeSelector = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$/
  const safeField = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/
  const safeId = /^[A-Za-z0-9_.:-]{1,128}$/
  const createPath = typeof hit.createPath === 'string' && hit.createPath.startsWith('/') ? hit.createPath : null
  let target = typeof hit.targetTemplate === 'string' && hit.targetTemplate.startsWith('/')
    ? hit.targetTemplate
    : typeof hit.path === 'string' && hit.path.startsWith('/') ? hit.path : null
  const targetId = typeof hit.targetId === 'string' && safeId.test(hit.targetId) ? hit.targetId : null
  const extractVar = typeof hit.extractVar === 'string' && /^[a-zA-Z_][a-zA-Z0-9_]{0,31}$/.test(hit.extractVar) ? hit.extractVar : 'resource_id'
  const fromState = String(hit.fromState ?? '').toLowerCase()
  const toState = String(hit.toState ?? '').toLowerCase()
  const seeded = typeof hit.seeded === 'boolean' ? hit.seeded : !createPath && Boolean(targetId)
  const repeatTransition = hit.repeatTransition === true
  if (!target) return []
  if (targetId && target.includes('{{id}}')) target = target.replaceAll('{{id}}', encodeURIComponent(targetId))
  else if (createPath && target.includes('{{id}}')) target = target.replaceAll('{{id}}', `{{${extractVar}}}`)
  if (!seeded && !createPath) return []
  const stateField = typeof hit.stateField === 'string' && safeField.test(hit.stateField) ? hit.stateField : ''
  const readPath = typeof hit.readPath === 'string' && hit.readPath.startsWith('/') ? hit.readPath : null
  const stateSelector = typeof hit.stateSelector === 'string' && safeSelector.test(hit.stateSelector) ? hit.stateSelector : undefined
  const collection = typeof hit.collection === 'string' && safeField.test(hit.collection) ? hit.collection : undefined
  const idField = typeof hit.idField === 'string' && safeField.test(hit.idField) ? hit.idField : undefined
  const recordId = typeof hit.recordId === 'string' && safeId.test(hit.recordId)
    ? hit.recordId
    : targetId
  const canReadState = Boolean(readPath && stateField)
  if (process.env.GUARDIAN_BENCH_DEBUG === '1') {
    process.stderr.write(`[spec-workflow] from=${fromState || '-'} to=${toState || '-'} create=${createPath ?? '-'} seeded=${seeded} repeat=${repeatTransition} read=${readPath ?? '-'} field=${stateField || '-'} coll=${collection ?? '-'} idField=${idField ?? '-'} recordId=${recordId ?? '-'} target=${target}\n`)
  }
  if (!canReadState && !repeatTransition && (!fromState || !toState)) return []
  if (fromState && !/^[a-z0-9_-]{1,32}$/.test(fromState)) return []
  if (toState && !/^[a-z0-9_-]{1,32}$/.test(toState)) return []
  const producerBody = hit.producerBody && typeof hit.producerBody === 'object' && !Array.isArray(hit.producerBody) ? hit.producerBody as Record<string, unknown> : {}
  const targetBody = hit.targetBody && typeof hit.targetBody === 'object' && !Array.isArray(hit.targetBody) ? hit.targetBody as Record<string, unknown> : {}
  const method = (o.hyp.method === 'PUT' ? 'PUT' : o.hyp.method === 'PATCH' ? 'PATCH' : 'POST') as 'POST' | 'PUT' | 'PATCH'
  const prereqs = Array.isArray(hit.falsePrerequisites) ? hit.falsePrerequisites.filter(x => typeof x === 'string' && /^[A-Za-z0-9_]{1,40}$/.test(x)) : []
  const prereqCheck = prereqs.map(k => `(.steps.p1.json[${jqStr(k)}] == false)`).join(' and ')
  const bodyFor = (body: Record<string, unknown>, encoding: string) => {
    if (encoding === 'form') {
      return {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        textBody: Object.entries(body).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
      }
    }
    return { headers: { 'Content-Type': 'application/json' }, jsonBody: body }
  }
  const createEncoding = String(hit.createEncoding ?? hit.producerEncoding ?? 'json') === 'form' ? 'form' : 'json'
  const targetEncoding = String(hit.targetEncoding ?? hit.encoding ?? 'json') === 'form' ? 'form' : 'json'
  const createSelector = typeof hit.createIdSelector === 'string' && /^(?:json:)?[A-Za-z_$][A-Za-z0-9_$.[\]-]{0,200}$/.test(hit.createIdSelector)
    ? hit.createIdSelector.replace(/^json:/, '')
    : 'id'

  const steps: Array<Record<string, unknown>> = []
  const writeExtra = env.caps.sessionAndCsrf ? { csrfBind: true } : {}
  const csrfPrimePath = typeof hit.csrfPrimePath === 'string' && /^\/(?!\/)[^\s\\]{0,4000}$/.test(hit.csrfPrimePath) ? hit.csrfPrimePath : '/'
  if (env.caps.sessionAndCsrf) steps.push(stepOf(env, 's1', 'setup', 'Prime session cookies and a CSRF token', { method: 'GET', pathAndQuery: csrfPrimePath }, env.owner))
  if (createPath) {
    const createBody = bodyFor(producerBody, createEncoding)
    steps.push({
      ...stepOf(env, 'c1', 'control', 'Create a fresh object in its initial state', {
        method: 'POST', pathAndQuery: createPath, ...createBody,
      }, env.owner, writeExtra),
      extract: [{ varName: extractVar, from: 'json' as const, selector: createSelector }],
    })
  }
  const baselineStepId = readPath ? 'c2' : 'c1'
  const useReadSteps = Boolean(readPath) && !repeatTransition
  if (useReadSteps && readPath) {
    steps.push(stepOf(env, baselineStepId, 'control', 'Read the object before the skipped transition', { method: 'GET', pathAndQuery: readPath }, env.owner))
  }
  if (repeatTransition) {
    // Same transition twice: the first establishes the legal from->to transition; the second must be
    // rejected once the object is no longer in the prerequisite state.
    steps.push(stepOf(env, 'c3', 'control', 'Perform the transition once (legal)', {
      method, pathAndQuery: target, ...bodyFor(targetBody, targetEncoding),
    }, env.owner, { ...writeExtra }, [200, 201, 204]))
  }
  steps.push(stepOf(env, 'p1', 'probe', 'Invoke the later transition directly', {
    method, pathAndQuery: target, ...bodyFor(targetBody, targetEncoding),
  }, env.owner, { ...writeExtra }, [200, 201, 204]))
  if (useReadSteps && readPath) {
    steps.push(stepOf(env, 'p2', 'probe', 'Read the object after the transition', { method: 'GET', pathAndQuery: readPath }, env.owner))
  }

  const stateExpr = (stepId: string): string => {
    const base = `.steps.${stepId}.json`
    if (stateSelector) return `(${base}${stateSelector.split('.').map(p => `[${jqStr(p)}]`).join('')})`
    if (collection && idField && recordId) return `([${base}[${jqStr(collection)}][]? | select((.[${jqStr(idField)}] | tostring) == ${jqStr(recordId)}) | .[${jqStr(stateField)}]][0])`
    if (collection && idField && createPath) return `([${base}[${jqStr(collection)}][]? | select((.[${jqStr(idField)}] | tostring) == $rid) | .[${jqStr(stateField)}]][0])`
    return `(${base}[${jqStr(stateField)}])`
  }
  const finalStateId = useReadSteps ? 'p2' : 'p1'
  let controlPassed: string
  let confirmed: string
  if (repeatTransition) {
    controlPassed = `(${is2xx('c3')})`
    confirmed = `(${is2xx('p1')})`
  } else if (canReadState) {
    const baseline = stateExpr(baselineStepId)
    const finalState = stateExpr(finalStateId)
    const createOk = createPath ? is2xx('c1') : 'true'
    controlPassed = `(${createOk} and ${is2xx(baselineStepId)} and ((${baseline} | tostring | ascii_downcase) == ${jqStr(fromState)}))`
    confirmed = `(${is2xx('p1')} and ${is2xx(finalStateId)} and ((${finalState} | tostring | ascii_downcase) == ${jqStr(toState)})` +
      `${prereqCheck ? ` and ${prereqCheck}` : ''})`
  } else {
    const createOk = createPath ? is2xx('c1') : 'true'
    controlPassed = `(${createOk} and ((.steps.c1.json.status // .steps.c1.json.state // "") | tostring | ascii_downcase) == ${jqStr(fromState)})`
    confirmed = `(${is2xx('p1')} and ((.steps.p1.json.status // .steps.p1.json.state // "") | tostring | ascii_downcase) == ${jqStr(toState)}` +
      `${prereqCheck ? ` and ${prereqCheck}` : ''})`
  }
  const jq = `(.extractedVars[${jqStr(extractVar)}] // "") as $rid | ` +
    `{ controlPassed: ${controlPassed}, confirmed: ${confirmed}, ` +
    `observed: ("final=" + (((${canReadState ? stateExpr(finalStateId) : '.steps.p1.json.status'}) // "") | tostring)), ` +
    `expected: "the prerequisite step must be completed first" }`
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env, 'Workflow step skipped (later transition accepted before prerequisite)', 'CWE-841', 'business-logic', 'high', jq),
      kind: 'http_chain',
      steps,
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
    if (p.name !== param && p.location === location && !p.isCsrf) siblings[p.name] = siblingValue(p.name, env)
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

/**
 * Race/TOCTOU double-spend: replay one producer mint followed by a synchronized burst of consume
 * requests carrying the same single-use value. Two or more 2xx acceptances prove the window.
 */
export function synthRace(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'race_double_spend')
  if (!hit) return []
  const producerPath = String(hit.producerPath ?? '')
  const consumePath = String(hit.path ?? '')
  const param = String(hit.param ?? '')
  const body = hit.consumeBody
  if (!consumePath.startsWith('/') || !body || typeof body !== 'object') return []
  if (param && !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(param)) return []
  const method = (o.hyp.method === 'PUT' ? 'PUT' : o.hyp.method === 'PATCH' ? 'PATCH' : 'POST') as 'POST' | 'PUT' | 'PATCH'
  const headers = { 'Content-Type': 'application/json' }
  const setupSteps: Array<Record<string, unknown>> = []
  const cleanupSteps: Array<Record<string, unknown>> = []

  const simplifiedStep = (raw: Record<string, unknown>, role: 'setup' | 'cleanup'): Record<string, unknown> | null => {
    const path = typeof raw.path === 'string' && raw.path.startsWith('/') ? raw.path : null
    if (!path) return null
    const rawMethod = String(raw.method ?? 'GET').toUpperCase()
    const m = rawMethod === 'POST' || rawMethod === 'PUT' || rawMethod === 'PATCH' ? rawMethod : 'GET'
    const parts: RequestParts = raw.body && typeof raw.body === 'object'
      ? { method: m as RequestParts['method'], pathAndQuery: path, jsonBody: raw.body }
      : { method: m as RequestParts['method'], pathAndQuery: path }
    const step = stepOf(env, String(raw.id ?? (role === 'setup' ? `s${setupSteps.length + 1}` : `z${cleanupSteps.length + 1}`)), role,
      String(raw.description ?? (role === 'setup' ? 'Mint/read the resource needed by the burst' : 'Restore the state after the burst')),
      parts, typeof raw.persona === 'string' ? raw.persona : env.owner)
    const extracts = Array.isArray(raw.extract) ? raw.extract.filter(e => e && typeof e === 'object' && typeof (e as Record<string, unknown>).varName === 'string') : []
    return extracts.length > 0 ? { ...step, extract: extracts } : step
  }

  const setup = Array.isArray(hit.setupSteps) ? hit.setupSteps : []
  for (const raw of setup) {
    if (raw && typeof raw === 'object' && setupSteps.length < 4) {
      const step = simplifiedStep(raw as Record<string, unknown>, 'setup')
      if (step) setupSteps.push(step)
    }
  }
  // Balance/stock races have no single-use producer: set up by reading the current value the burst
  // consumes, then read it back afterwards to prove the conservation break.
  const balancePath = typeof hit.balancePath === 'string' && hit.balancePath.startsWith('/') ? hit.balancePath : null
  const balanceField = typeof hit.balanceField === 'string' && /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(hit.balanceField) ? hit.balanceField : null
  if (setupSteps.length === 0 && balancePath && balanceField) {
    setupSteps.push({
      ...stepOf(env, 's1', 'setup', 'Read the current balance that the burst will consume', { method: 'GET', pathAndQuery: balancePath }, env.owner),
      extract: [{ varName: 'balance0', from: 'json' as const, selector: balanceField }],
    })
  }
  const cleanup = Array.isArray(hit.cleanupSteps) ? hit.cleanupSteps : []
  for (const raw of cleanup) {
    if (raw && typeof raw === 'object' && cleanupSteps.length < 3) {
      const step = simplifiedStep(raw as Record<string, unknown>, 'cleanup')
      if (step) cleanupSteps.push(step)
    }
  }

  const burst = Array.from({ length: 4 }, () => ({
    origin: env.origin, method, pathAndQuery: consumePath, headers,
    ...(env.owner ? { persona: env.owner } : {}),
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
    jsonBody: body as Record<string, unknown>,
  }))
  const controlStep = producerPath.startsWith('/') && /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(param)
    ? { ...stepOf(env, 'm1', 'control', 'Mint one single-use value', { method: 'POST', pathAndQuery: producerPath, jsonBody: {} }, env.owner), extract: [{ varName: 'code', from: 'json' as const, selector: param }] }
    : undefined
  const jq = '{ controlPassed: ((.control.status >= 200 and .control.status < 300) or (.setup | length) >= 1), ' +
    'confirmed: (([(.burst.results // [])[] | select(.status >= 200 and .status < 300)] | length) >= 2), ' +
    'observed: ("accepted=" + (([(.burst.results // [])[] | select(.status >= 200 and .status < 300)] | length) | tostring)), expected: "one single-use value is accepted exactly once" }'

  // Cut 3d: attach a typed floor-recipe envelope (`conserved_balance` for balance/stock races,
  // `race_burst` for single-use voucher/coupon races) so verification runs through ProofReceipt.
  const recipeActor = { handle: env.owner ?? 'anonymous' }
  const toRecipeStep = (raw: Record<string, unknown>) => {
    const path = typeof raw.path === 'string' && raw.path.startsWith('/') ? raw.path : null
    if (!path) return null
    const rawMethod = String(raw.method ?? 'GET').toUpperCase()
    const m = rawMethod === 'POST' || rawMethod === 'PUT' || rawMethod === 'PATCH' ? rawMethod : 'GET'
    const extracts = Array.isArray(raw.extract)
      ? raw.extract
        .filter((e): e is { varName: string; selector: string } =>
          Boolean(e && typeof e === 'object' && typeof (e as Record<string, unknown>).varName === 'string' && typeof (e as Record<string, unknown>).selector === 'string'))
        .map(e => ({ varName: e.varName, selector: e.selector }))
      : []
    return {
      method: m,
      pathAndQuery: path,
      ...(raw.body && typeof raw.body === 'object' ? { jsonBody: raw.body } : {}),
      ...(typeof raw.persona === 'string' ? { actor: { handle: raw.persona } } : {}),
      ...(extracts.length > 0 ? { extract: extracts } : {}),
    }
  }
  const recipeSetupSteps = setup
    .slice(0, 4)
    .map(raw => (raw && typeof raw === 'object' ? toRecipeStep(raw as Record<string, unknown>) : null))
    .filter((s): s is NonNullable<typeof s> => Boolean(s))
  if (recipeSetupSteps.length === 0 && producerPath.startsWith('/') && /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(param)) {
    recipeSetupSteps.push({
      method: 'POST',
      pathAndQuery: producerPath,
      jsonBody: {},
      extract: [{ varName: 'code', selector: param }],
    })
  }
  const recipeCleanupSteps = cleanup
    .slice(0, 3)
    .map(raw => (raw && typeof raw === 'object' ? toRecipeStep(raw as Record<string, unknown>) : null))
    .filter((s): s is NonNullable<typeof s> => Boolean(s))
  const readbackPath = balancePath ?? (typeof hit.parentPath === 'string' && hit.parentPath.startsWith('/') ? hit.parentPath : null)
  const bodyRecord = body as Record<string, unknown>
  const numericDebitInBody = Object.entries(bodyRecord).some(([k, v]) =>
    /^(?:amount|quantity|qty|debit|delta|value|count|seats|points|credits|transfer_amount|redeem_amount)$/i.test(k) &&
    typeof v === 'number' && Number.isFinite(v) && v > 0)
  const useConservedBalance = Boolean(readbackPath) && hit.mode !== 'single_use' && (Boolean(balanceField) || numericDebitInBody)
  const recipe = useConservedBalance
    ? {
        recipeId: 'conserved_balance' as const,
        args: {
          origin: env.origin,
          method,
          pathAndQuery: consumePath,
          vulnClass: 'race_double_spend',
          actor: recipeActor,
          body: bodyRecord,
          burst: 4,
          headers,
          readback: { method: 'GET', pathAndQuery: readbackPath! },
          ...(recipeSetupSteps.length > 0 ? { setupSteps: recipeSetupSteps } : {}),
          ...(recipeCleanupSteps.length > 0 ? { cleanupSteps: recipeCleanupSteps } : {}),
          ...(balanceField ? { balanceField } : {}),
          ...(typeof hit.value === 'number' && Number.isFinite(hit.value) && hit.value > 0 ? { unitDebit: hit.value } : {}),
        },
      }
    : {
        recipeId: 'race_burst' as const,
        args: {
          origin: env.origin,
          method,
          pathAndQuery: consumePath,
          vulnClass: 'business_logic',
          actor: recipeActor,
          body: bodyRecord,
          burst: 4,
          headers,
          ...(recipeSetupSteps.length > 0 ? { setupSteps: recipeSetupSteps } : {}),
          ...(recipeCleanupSteps.length > 0 ? { cleanupSteps: recipeCleanupSteps } : {}),
        },
      }
  return [{
    kind: 'race_burst',
    spec: {
      ...baseFields(env, 'Race condition allows a single-use value to be consumed twice', 'CWE-362', 'business-logic', 'high', jq),
      kind: 'race_burst',
      ...(setupSteps.length > 0 ? { setupSteps } : {}),
      ...(controlStep ? { controlStep } : {}),
      burst,
      ...(typeof hit.parentPath === 'string' && hit.parentPath.startsWith('/')
        ? { postCheckStep: stepOf(env, 'p1', 'probe', 'Read the balance after the burst', { method: 'GET', pathAndQuery: hit.parentPath }) }
        : {}),
      ...(cleanupSteps.length > 0 ? { cleanupSteps } : {}),
      recipe,
    },
  }]
}

// ---------------------------------------------------------------------------
// DOM XSS: URL query source flowing into an executable script sink
// ---------------------------------------------------------------------------

export function synthUrlDomXss(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'dom_xss_url_sink')
  if (!hit || hit.canaryTriggered !== true) return []
  const basePath = String(hit.path ?? o.hyp.endpoint.path)
  const param = String(hit.urlParam ?? o.hyp.param?.name ?? '')
  if (!basePath.startsWith('/') || !/^[A-Za-z_][A-Za-z0-9_.-]{0,40}$/.test(param)) return []
  const payload = `<img src=x onerror="document.title='{{canary_token}}'">`
  const encodedPayload = payload.split('{{canary_token}}').map(encodeURIComponent).join('{{canary_token}}')
  const controlPath = appendQuery(basePath, param, 'guardian')
  const probePath = appendQuery(basePath, param, encodedPayload, false)
  const params = { origin: env.origin, ...(env.owner ? { persona: env.owner } : {}), ...sessionFields(env, o.hyp) }
  const jq = '{ controlPassed: (.steps.c1.status >= 200 and .steps.c1.status < 400 and (.steps.c1.title != .canaryToken) and (([(.steps.c1.domSinkTraces // [])[] | select(.containsCanary)] | length) == 0)), ' +
    'confirmed: ((.steps.p1.status >= 200 and .steps.p1.status < 400) and ((.steps.p1.title == .canaryToken) or (([(.steps.p1.domSinkTraces // [])[] | select(.containsCanary)] | length) >= 1))), ' +
    'observed: ("probe sink hits=" + (([(.steps.p1.domSinkTraces // [])[] | select(.containsCanary)] | length) | tostring)), expected: "URL input is rendered as inert text" }'
  const steps = [
    { id: 'c1', role: 'control', description: 'Render the page with a benign query value', ...params, pathAndQuery: controlPath, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 300 },
    { id: 'p1', role: 'probe', description: 'Render the page with an executable query payload', ...params, pathAndQuery: probePath, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 900 },
  ]
  // Cut 3d: confirmation runs the `browser_sink` recipe (host-recorded canary sink), not the
  // legacy browser VM; the steps above remain the attribution shape.
  const recipe = browserSinkEnvelopeFromSteps({ origin: env.origin, vulnClass: 'dom_xss', steps })
  return [{
    kind: 'browser_chain',
    spec: {
      ...baseFields(env, 'DOM-based cross-site scripting via URL query sink', 'CWE-79', 'xss', 'high', jq),
      kind: 'browser_chain',
      steps,
      ...(recipe ? { recipe } : {}),
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

  const recipe = browserSinkEnvelopeFromSteps({ origin: env.origin, vulnClass: 'dom_xss', steps })
  return [{
    kind: 'browser_chain',
    spec: {
      ...baseFields(env, 'DOM-based cross-site scripting via interactive sink', 'CWE-79', 'xss', 'high', jq),
      kind: 'browser_chain',
      steps,
      ...(recipe ? { recipe } : {}),
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
  // Keep the verifier placeholder intact while percent-encoding the rest of the payload.
  const encodedPayload = payload.split('{{canary_token}}').map(encodeURIComponent).join('{{canary_token}}')
  const probePath = appendQuery(basePath, o.hyp.param.name, encodedPayload, false)
  const params = { origin: env.origin, ...(env.owner ? { persona: env.owner } : {}), ...sessionFields(env, o.hyp) }
  const jq = '{ controlPassed: (.steps.c1.status >= 200 and .steps.c1.status < 400 and (.steps.c1.title != .canaryToken) and (([(.steps.c1.domSinkTraces // [])[] | select(.containsCanary)] | length) == 0)), ' +
    'confirmed: ((.steps.p1.status >= 200 and .steps.p1.status < 400) and ((.steps.p1.title == .canaryToken) or (([(.steps.p1.domSinkTraces // [])[] | select(.containsCanary)] | length) >= 1))), ' +
    'observed: ("probe title=" + (.steps.p1.title // "" | tostring)), expected: "reflected input is inert text" }'
  const steps = [
    { id: 'c1', role: 'control', description: 'Render the page with a benign parameter value', ...params, pathAndQuery: controlPath, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 300 },
    { id: 'p1', role: 'probe', description: 'Render the page with an executable marker payload', ...params, pathAndQuery: probePath, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 800 },
  ]
  const recipe = browserSinkEnvelopeFromSteps({ origin: env.origin, vulnClass: 'dom_xss', steps })
  return [{
    kind: 'browser_chain',
    spec: {
      ...baseFields(env, 'Reflected cross-site scripting (executed marker)', 'CWE-79', 'xss', 'high', jq),
      kind: 'browser_chain',
      steps,
      ...(recipe ? { recipe } : {}),
    },
  }]
}

/**
 * Aggregate cap: two settled records from the same money mutation. The probe only emits this after
 * both calls returned a terminal status with distinct ids, so a normal create (pending) or a
 * correctly capped route (second call rejected) never reaches this builder.
 */
export function synthWorkflowRepeatAccepted(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'workflow_repeat_accepted')
  if (!hit) return []
  const path = String(hit.path ?? '')
  if (!/^\/(?!\/)[^\s\\]{0,4000}$/.test(path)) return []
  const method = (o.hyp.method === 'PUT' ? 'PUT' : o.hyp.method === 'PATCH' ? 'PATCH' : 'POST') as 'POST' | 'PUT' | 'PATCH'
  const bodyRaw = hit.body && typeof hit.body === 'object' && !Array.isArray(hit.body) ? hit.body as Record<string, unknown> : {}
  if (Object.keys(bodyRaw).length === 0) return []
  const body = Object.fromEntries(Object.entries(bodyRaw).filter(([k, v]) =>
    /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(k) && (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')))
  if (Object.keys(body).length === 0) return []
  const encoding = hit.encoding === 'form' ? 'form' : 'json'
  const statusField = typeof hit.statusField === 'string' && /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(hit.statusField)
    ? hit.statusField : 'status'
  const statusValue = String(hit.statusValue ?? '').toLowerCase()
  if (!/^[a-z0-9_-]{1,32}$/.test(statusValue)) return []
  const firstId = typeof hit.firstId === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(hit.firstId) ? hit.firstId : null
  const secondId = typeof hit.secondId === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(hit.secondId) ? hit.secondId : null
  const request = encoding === 'form'
    ? {
        method, pathAndQuery: path,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        textBody: Object.entries(body).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
      }
    : { method, pathAndQuery: path, headers: { 'Content-Type': 'application/json' }, jsonBody: body }
  const fieldLit = jqStr(statusField)
  const statusExpr = (stepId: string) => `((.steps.${stepId}.json[${fieldLit}] | tostring | ascii_downcase) == ${jqStr(statusValue)})`
  const distinctIds = firstId && secondId && firstId !== secondId
    ? ` and ((.steps.c1.json.id | tostring) != (.steps.p1.json.id | tostring))`
    : ''
  const jq = `{ controlPassed: ((${is2xx('c1')}) and ${statusExpr('c1')}), ` +
    `confirmed: ((${is2xx('p1')}) and ${statusExpr('p1')}${distinctIds}), ` +
    `observed: ("first=" + (.steps.c1.status | tostring) + " second=" + (.steps.p1.status | tostring) + " state=" + ((.steps.p1.json[${fieldLit}]) | tostring)), ` +
    'expected: "a settled money mutation is accepted at most once per captured total" }'
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env, 'Business logic allows a second settled money record', 'CWE-840', 'business-logic', 'high', jq),
      kind: 'http_chain',
      steps: [
        ...(env.caps.sessionAndCsrf ? [stepOf(env, 's1', 'setup', 'Prime session cookies and a CSRF token', { method: 'GET', pathAndQuery: typeof hit.csrfPrimePath === 'string' && /^\/(?!\/)[^\s\\]{0,4000}$/.test(hit.csrfPrimePath) ? hit.csrfPrimePath : '/' }, env.owner)] : []),
        stepOf(env, 'c1', 'control', 'First settled money mutation', request, env.owner, env.caps.sessionAndCsrf ? { csrfBind: true } : {}),
        stepOf(env, 'p1', 'probe', 'Repeat the same money mutation', request, env.owner, env.caps.sessionAndCsrf ? { csrfBind: true } : {}),
      ],
    },
  }]
}
