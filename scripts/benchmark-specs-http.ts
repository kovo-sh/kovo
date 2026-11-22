/** http_chain / rce_proof spec synthesis: authz, mass assignment, SSRF, XXE, SSTI. */
import { randomBytes } from 'node:crypto'
import { appendQuery, baseFields, bogusIdFor, is2xx, jqStr, requestParts, sameAsControl, stepOf } from './benchmark-specs-common.ts'
import type { RequestParts, SynthesizedSpec } from './benchmark-specs-common.ts'
import { fillPlaceholders, hasPathPlaceholder, probePathFor, siblingValue } from './benchmark-probes.ts'
import type { HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'

const canaryJq = (control: string) =>
  `{ controlPassed: (.steps.${control}.status < 500), confirmed: (.canary.triggered == true), observed: ("probeCallback=" + ((.canary.probeTriggered // false) | tostring)), expected: "no out-of-band callback" }`

const NEGATIVE_CONTROL_STATUS = [400, 401, 403, 404, 405, 409, 410, 422]

interface MatrixRow {
  resourceId?: unknown
  actor?: unknown
  status?: unknown
  bodyBytes?: unknown
  bodySha256?: unknown
  similarityToOwner?: unknown
  accessible?: unknown
}

/** A step must carry a non-trivial object, not an empty action acknowledgement. */
const nonTrivial = (id: string, minBytes = 3) =>
  `(((${is2xx(id)})) and (((.steps.${id}.body | length) > ${minBytes}) or (((.steps.${id}.json | type) == "object") and (((.steps.${id}.json | keys | length) >= 2)))))`

function matchesOwnerJq(): string {
  return `((.steps.p1.body == .steps.c1.body) or (.steps.c1.json as $c | .steps.p1.json as $p | ` +
    `(($c | type) == "object") and (([$c | keys[]] | length) > 0) and ` +
    `(([($c | to_entries[]) | select($p[.key] == .value)] | length) == ([$c | keys[]] | length))))`
}

/**
 * The negative control must prove the route is actually bound to the identifier. A handler that
 * ignores the id and operates on the session's own object returns the owner's response unchanged
 * for a bogus id, so the spec is not submitted. Mutating routes additionally never accept a
 * nonexistent object id.
 */
function negativeControlJq(mutating: boolean): string {
  if (mutating) return `((.steps.c2.status >= 400) and (.steps.c2.status < 500))`
  return `(((.steps.c2.status >= 400) and (.steps.c2.status < 500)) or ((${is2xx('c2')}) and (.steps.c2.body != .steps.c1.body) and ((.steps.c2.body | length) > 2)))`
}

function matrixRows(o: HypothesisOutcome): MatrixRow[] | null {
  const matrix = o.details.matrix
  if (!Array.isArray(matrix)) return null
  return matrix.filter((row): row is MatrixRow => Boolean(row) && typeof row === 'object')
}

export function synthAuthz(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const owner = o.pair?.owner ?? env.owner
  const other = o.pair?.other ?? env.other
  if (!owner || !other) return []
  const claimsId = o.hyp.endpoint.params.some(p => (p.isObjectId || /(^|[_-])id$/i.test(p.name)) && p.location === 'query')
  const hits = o.anomalies
    .filter(a => a.type === 'unauthorized_access')
    // Strongest evidence first: body-equivalent cross-actor reads, then mutations.
    .sort((a, b) => {
      const ga = String(a.method ?? 'GET') === 'GET' ? 0 : 1
      const gb = String(b.method ?? 'GET') === 'GET' ? 0 : 1
      if (ga !== gb) return ga - gb
      return (Number(b.similarityToOwner ?? 0)) - (Number(a.similarityToOwner ?? 0))
    })
  if (hits.length === 0) return []
  const rows = matrixRows(o)
  const rejects = { owner: 0, probe: 0, public: 0, trivial: 0 }
  const out: SynthesizedSpec[] = []
  const seen = new Set<string>()

  for (const hit of hits) {
    const id = String(hit.resourceId ?? '')
    const method = String(hit.method ?? 'GET')
    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) continue
    const mutating = method !== 'GET'
    const functionLevel = hit.functionLevel === true ||
      (!hasPathPlaceholder(o.hyp.endpoint.path) && !claimsId)
    const key = `${method}|${functionLevel ? 'fn' : id}`
    if (seen.has(key)) continue
    seen.add(key)
    if (!functionLevel && !/^[A-Za-z0-9_.:-]{1,128}$/.test(id)) continue

    const probeActor = hit.actor === 'anonymous' ? 'anonymous' : 'other_persona'
    let ownerOk = true
    let probeOk = true
    if (rows) {
      const idRows = functionLevel ? rows : rows.filter(r => String(r.resourceId ?? '') === id)
      const ownerRow = idRows.find(r => r.actor === 'owner')
      const probeRow = idRows.find(r => r.actor === probeActor)
      // (2) The owner must demonstrably address the resource, and the replay must carry body evidence.
      if (!ownerRow || ownerRow.accessible !== true || typeof ownerRow.status !== 'number' || ownerRow.status < 200 || ownerRow.status >= 300) { ownerOk = false; rejects.owner += 1 }
      else if (typeof ownerRow.bodyBytes === 'number' && ownerRow.bodyBytes <= (mutating ? 12 : 2)) { ownerOk = false; rejects.trivial += 1 }
      if (!probeRow || probeRow.accessible !== true) { probeOk = false; rejects.probe += 1 }
      else if (!mutating && Number(probeRow.similarityToOwner ?? hit.similarityToOwner ?? 0) < 0.7) { probeOk = false; rejects.probe += 1 }
      const anonRow = idRows.find(r => r.actor === 'anonymous')
      // Public data readable by anonymous callers with the same body is not an authorization failure.
      if (!mutating && anonRow?.accessible === true && ownerRow) {
        const sameBody = typeof anonRow.bodySha256 === 'string' && anonRow.bodySha256 === ownerRow.bodySha256
        const similar = Number(anonRow.similarityToOwner ?? 0) >= 0.7
        if (sameBody || similar) { ownerOk = false; rejects.public += 1 }
      }
    }
    if (!ownerOk || !probeOk) continue

    const bodyTemplate: unknown = hit.bodyTemplate !== undefined && hit.bodyTemplate !== null ? hit.bodyTemplate : {}
    const path = functionLevel
      ? o.hyp.endpoint.path
      : hasPathPlaceholder(o.hyp.endpoint.path)
        ? fillPlaceholders(o.hyp.endpoint.path, encodeURIComponent(id))
        : `${o.hyp.endpoint.path}?${o.hyp.endpoint.params.find(p => p.location === 'query')?.name ?? 'id'}=${encodeURIComponent(id)}`
    const parts: RequestParts = { method: method as RequestParts['method'], pathAndQuery: path, ...(mutating ? { jsonBody: bodyTemplate } : {}) }
    const probePersona = hit.actor === 'anonymous' ? null : other
    // Object-level routes always get a negative control. Real probe outcomes use a format-aware
    // nonexistent id; hand-built fixtures fall back to a random sentinel identifier.
    const neg = functionLevel ? null : negativeControlJq(mutating)
    const ownerJq = nonTrivial('c1', mutating ? 12 : 3)
    const probeJq = nonTrivial('p1', mutating ? 12 : 3)
    const jq = `{ controlPassed: ((${ownerJq})${neg ? ` and (${neg})` : ''}), ` +
      `confirmed: ((${probeJq})${neg ? ` and (${neg})` : ''} and (${matchesOwnerJq()})), ` +
      `observed: ("probe status=" + (.steps.p1.status | tostring)${neg ? ' + " bogus status=" + (.steps.c2.status | tostring)' : ''}), ` +
      'expected: "non-owner denied" }'
    const steps: Array<Record<string, unknown>> = []
    if (!functionLevel) {
      const negativeId = rows === null ? `guardian-none-${randomBytes(5).toString('hex')}` : bogusIdFor(id)
      const negativePath = hasPathPlaceholder(o.hyp.endpoint.path)
        ? fillPlaceholders(o.hyp.endpoint.path, encodeURIComponent(negativeId))
        : `${o.hyp.endpoint.path}?${o.hyp.endpoint.params.find(p => p.location === 'query')?.name ?? 'id'}=${encodeURIComponent(negativeId)}`
      steps.push(stepOf(env, 'c2', 'control', `Authorized actor addresses a nonexistent identifier (${negativeId})`,
        { method: method as RequestParts['method'], pathAndQuery: negativePath, ...(mutating ? { jsonBody: bodyTemplate } : {}) },
        owner, {}, NEGATIVE_CONTROL_STATUS))
    }
    steps.push(stepOf(env, 'c1', 'control', 'Authorized actor performs the request', parts, owner))
    steps.push(stepOf(env, 'p1', 'probe', `${probePersona ? 'Lower-privileged actor' : 'Unauthenticated caller'} performs the same request`, parts, probePersona))
    out.push({
      kind: 'http_chain',
      spec: {
        ...baseFields(env, 'Cross-actor object or function access', 'CWE-639', 'broken-access-control', 'high', jq),
        kind: 'http_chain',
        steps,
      },
    })
  }
  if (out.length === 0 && process.env.GUARDIAN_BENCH_DEBUG === '1') {
    process.stderr.write(`[spec-skip] authz_matrix ${o.hyp.endpoint.path}: owner=${rejects.owner} probe=${rejects.probe} public=${rejects.public} trivial=${rejects.trivial}\n`)
  }
  return out
}

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
 * Mass assignment proven as a *transition*: write a low-privilege value (control), read it back,
 * then overpost the privileged value (probe) and read again. Valid even when the account already
 * holds the privileged value before the replay.
 */
function synthMassAssignmentTransition(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'mass_assignment')
  if (!hit || !env.owner) return []
  const field = String(hit.field ?? '')
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(field)) return []
  const lowValue = massAssignmentValue(field, false)
  const expected = massAssignmentValue(field, true)
  if (lowValue === expected) return []
  const method = (o.hyp.method === 'PUT' ? 'PUT' : o.hyp.method === 'PATCH' ? 'PATCH' : 'POST') as 'POST' | 'PUT' | 'PATCH'
  const path = hasPathPlaceholder(o.hyp.endpoint.path) ? fillPlaceholders(o.hyp.endpoint.path, '1') : o.hyp.endpoint.path
  const read: RequestParts = { method: 'GET', pathAndQuery: path }
  const write = (value: string | boolean): RequestParts => ({ method, pathAndQuery: path, jsonBody: { [field]: value } })
  const fieldLit = jqStr(field)
  const expectedLit = typeof expected === 'boolean' ? String(expected) : jqStr(expected)
  const lowLit = typeof lowValue === 'boolean' ? String(lowValue) : jqStr(lowValue)
  const jq = `{ controlPassed: (${is2xx('c1')} and ((.steps.c1.json | type) == "object") and (.steps.c1.json[${fieldLit}] == ${lowLit})), ` +
    `confirmed: ((${is2xx('p2')} and (.steps.p2.json[${fieldLit}] == ${expectedLit}))), ` +
    `observed: (("${field}=" + ((.steps.p2.json[${fieldLit}]) | tostring))), expected: "privileged field must not be writable" }`
  const spec = {
    ...baseFields(env, 'Mass assignment of a privileged profile field', 'CWE-915', 'mass-assignment', 'high', jq),
    kind: 'http_chain',
    steps: [
      stepOf(env, 'w1', 'control', `Baseline write of a low-privilege "${field}" value`, write(lowValue), env.owner),
      stepOf(env, 'c1', 'control', 'Read the record to confirm the baseline value', read, env.owner),
      stepOf(env, 'p1', 'probe', `Overpost the privileged "${field}" field`, write(expected), env.owner),
      stepOf(env, 'p2', 'probe', 'Re-read the record to observe persistence', read, env.owner),
    ],
  }
  return [{ kind: 'http_chain', spec }]
}

export function synthMassAssignment(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'mass_assignment' && a.persisted === true)
  if (!hit || !env.owner) return []
  const field = String(hit.field ?? '')
  // Field names are replayed inside jq and JSON bodies; reject anything that is not a plain identifier.
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(field)) return []
  const out = synthMassAssignmentTransition(o, env)
  if (out.length > 0) return out
  const isBool = /^(?:is|has|verified|admin|emailVerified)/i.test(field)
  const value: string | boolean = isBool ? true : `guardian_ma_${randomBytes(3).toString('hex')}`
  const read: RequestParts = { method: 'GET', pathAndQuery: o.hyp.endpoint.path }
  const write: RequestParts = {
    method: o.hyp.endpoint.method === 'PUT' || o.hyp.endpoint.method === 'PATCH' ? o.hyp.endpoint.method as 'PUT' | 'PATCH' : (o.hyp.method === 'GET' ? 'PATCH' : o.hyp.method),
    pathAndQuery: o.hyp.endpoint.path, jsonBody: { [field]: value },
  }
  const has = isBool
    ? (id: string) => `((.steps.${id}.json | .[${jqStr(field)}]) == true)`
    : (id: string) => `(.steps.${id}.body | contains(${jqStr(String(value))}))`
  const spec = {
    ...baseFields(env, 'Mass assignment of privileged field', 'CWE-915', 'broken-access-control', 'high',
      `{ controlPassed: (${is2xx('c1')} and .steps.p1.status < 300), confirmed: (${has('p2')} and (${has('c1')} | not)), observed: ("p2.status=" + (.steps.p2.status | tostring)), expected: "privileged field is not client-writable" }`),
    kind: 'http_chain',
    steps: [
      stepOf(env, 'c1', 'control', 'Read the record before overposting', read, env.owner),
      stepOf(env, 'p1', 'probe', 'Overpost a privileged field', write, env.owner),
      stepOf(env, 'p2', 'probe', 'Read the record back', read, env.owner),
    ],
  }
  return [{ kind: 'http_chain', spec }]
}

/**
 * Second-order SSRF: register a benign/canary URL through the write route, then trigger the app's
 * own fetch step. The verifier mints distinct control/probe canaries so a callback must come from
 * the probe registration, not from shared infrastructure.
 */
export function synthSecondOrderSsrf(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'second_order_ssrf_callback')
  if (!hit || !o.hyp.param) return []
  const param = o.hyp.param.name
  const location = o.hyp.location ?? 'json'
  const path = probePathFor(o.hyp)
  const pattern = typeof hit.triggerPattern === 'string' && hit.triggerPattern.startsWith('/') ? hit.triggerPattern : null
  if (!pattern) return []
  const siblings: Record<string, unknown> = {}
  for (const p of o.hyp.endpoint.params) {
    if (p.name === param || p.isCsrf || p.location !== location) continue
    siblings[p.name] = siblingValue(p.name, env)
  }
  const register = (value: string): RequestParts | null => {
    switch (location) {
      case 'query': return { method: o.hyp.method, pathAndQuery: appendQuery(path, param, value, false) }
      case 'form': {
        const all = { ...siblings, [param]: value }
        return {
          method: o.hyp.method, pathAndQuery: path,
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          textBody: Object.entries(all).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
        }
      }
      case 'json': default: return { method: o.hyp.method, pathAndQuery: path, jsonBody: { ...siblings, [param]: value } }
    }
  }
  const control = register('http://guardian-control.invalid/')
  const probe = register('{{canary_url}}')
  if (!control || !probe) return []
  const registerStep = stepOf(env, 'p1', 'probe', 'Register the canary URL through the write route', probe)
  const steps = [
    stepOf(env, 'c1', 'control', 'Register a benign URL (no callback expected)', control),
    { ...registerStep, extract: [{ varName: 'resource_id', from: 'json' as const, selector: 'id' }] },
    stepOf(env, 'p2', 'probe', 'Trigger the stored URL fetch', { method: 'POST', pathAndQuery: pattern.replace('{{id}}', '{{resource_id}}'), jsonBody: {} }),
  ]
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env, 'Second-order server-side request forgery (stored URL fetched later)', 'CWE-918', 'ssrf', 'high', canaryJq('c1')),
      kind: 'http_chain',
      steps,
    },
  }]
}

export function synthSsrf(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const secondOrder = synthSecondOrderSsrf(o, env)
  if (secondOrder.length > 0) return secondOrder
  const hit = o.anomalies.find(a => a.type === 'canary_callback' && a.variant === 'http')
  if (!hit) return []
  const control = requestParts(o, env, 'http://guardian-control.invalid/')
  const probe = requestParts(o, env, '{{canary_url}}')
  if (!control || !probe) return []
  const spec = {
    ...baseFields(env, 'Server-side request forgery (out-of-band callback)', 'CWE-918', 'ssrf', 'high', canaryJq('c1')),
    kind: 'http_chain',
    steps: [
      stepOf(env, 'c1', 'control', 'Benign URL value (no callback expected)', control),
      stepOf(env, 'p1', 'probe', 'Guardian canary URL value', probe),
    ],
  }
  return [{ kind: 'http_chain', spec }]
}

const xmlBenign = '<?xml version="1.0" encoding="UTF-8"?><guardian><ping>ok</ping></guardian>'
const xxeBodies: Record<string, string> = {
  general_entity: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY gxxe SYSTEM "{{canary_url}}">]><root>&gxxe;</root>',
  param_entity: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % gxxep SYSTEM "{{canary_url}}"> %gxxep;]><root>ok</root>',
  svg_dtd: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY svgx SYSTEM "{{canary_url}}">]><svg xmlns="http://www.w3.org/2000/svg"><text>&svgx;</text></svg>',
}

export function synthXxe(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'xxe_canary_callback')
  if (!hit) return []
  const body = xxeBodies[String(hit.variant)] ?? xxeBodies.general_entity
  const headers = { 'Content-Type': 'application/xml' }
  const path = o.hyp.endpoint.path
  const method = o.hyp.method === 'GET' ? 'POST' : o.hyp.method
  const spec = {
    ...baseFields(env, 'XML external entity injection (out-of-band callback)', 'CWE-611', 'xxe', 'high', canaryJq('c1')),
    kind: 'http_chain',
    steps: [
      stepOf(env, 'c1', 'control', 'Benign XML document', { method, pathAndQuery: path, headers, textBody: xmlBenign }),
      stepOf(env, 'p1', 'probe', 'XML document with external entity to Guardian canary', { method, pathAndQuery: path, headers, textBody: body }),
    ],
  }
  return [{ kind: 'http_chain', spec }]
}

const sstiTemplates: Record<string, string> = {
  'jinja2/twig': '{{{{nonce_a}}*{{nonce_b}}}}',
  erb: '<%={{nonce_a}}*{{nonce_b}}%>',
  'freemarker/el': '${{{nonce_a}}*{{nonce_b}}}',
  'spel/pebble': '#{{{nonce_a}}*{{nonce_b}}}',
  thymeleaf: '[[${{{nonce_a}}*{{nonce_b}}}]]',
}

/**
 * Command injection proven with a split-echo nonce: the assembled nonce only appears when the shell
 * executes two concatenated echo operands, so plain reflection cannot satisfy the proof.
 */
export function synthCommandInjection(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'command_executed')
  if (!hit || !o.hyp.param) return []
  const base = String(hit.baseValue ?? '127.0.0.1').slice(0, 64)
  const variant = String(hit.variant)
  // The two nonces must be joined by execution syntax, not literal adjacency: the verifier rejects
  // specs where the assembled token already appears in the outbound request.
  const templates: Record<string, string> = {
    semicolon_echo: `${base}; echo {{nonce_part1}}$(echo {{nonce_part2}})`,
    subshell_echo: `${base}$(echo {{nonce_part1}})$(echo {{nonce_part2}})`,
    quote_break: `${base}"; echo {{nonce_part1}}$(echo {{nonce_part2}}); "`,
    quote_break_id: `${base}"; id; echo {{nonce_part1}}$(echo {{nonce_part2}}); "`,
    pipe_echo: `${base} | echo {{nonce_part1}}$(echo {{nonce_part2}})`,
    backtick_echo: `${base}\`echo {{nonce_part1}}$(echo {{nonce_part2}})\``,
  }
  const template = templates[variant] ?? templates.semicolon_echo
  const control = requestParts(o, env, base)
  const probe = requestParts(o, env, template)
  if (!control || !probe) return []
  const out: SynthesizedSpec[] = [{
    kind: 'rce_proof',
    spec: {
      ...baseFields(env, 'Command injection via shell metacharacters (nonce echo proof)', 'CWE-78', 'injection-input', 'critical',
        '{ controlPassed: (.control.status < 500), confirmed: (.proof.splitEchoVerified == true), observed: ("splitEcho=" + ((.proof.splitEchoVerified // false) | tostring)), expected: "shell metacharacters are inert data" }'),
      kind: 'rce_proof',
      proofMode: 'split_echo',
      requiresTier3Approval: true,
      controlStep: stepOf(env, 'c1', 'control', 'Benign value', control),
      probeStep: stepOf(env, 'p1', 'probe', 'Verifier-minted split echo operands', probe),
    },
  }]
  // Second proof shape: the observed payload's nonce appears in the response while the payload
  // itself was not reflected. Rejected by the split-echo verifier when the simulator renders the
  // substitution on its own line, but an http_chain assertion can still prove execution.
  const observedPayload = typeof hit.payload === 'string' ? hit.payload : ''
  const nonce = typeof hit.nonce === 'string' ? hit.nonce : ''
  if (observedPayload.length > 0 && observedPayload.length <= 200 && !/[\r\n\0]/.test(observedPayload) &&
      /^[A-Za-z0-9]{8,40}$/.test(nonce)) {
    const observedProbe = requestParts(o, env, observedPayload)
    if (observedProbe) {
      const jq = `{ controlPassed: ((.steps.c1.status < 500) and ((.steps.c1.body | contains(${jqStr(nonce)})) | not)), ` +
        `confirmed: ((${is2xx('p1')}) and (.steps.p1.body | contains(${jqStr(nonce)})) and ((.steps.p1.body | contains(${jqStr(observedPayload)})) | not)), ` +
        `observed: ("nonce=" + (${jqStr(nonce)}) + " reflected=" + ((.steps.p1.body | contains(${jqStr(observedPayload)})) | tostring)), expected: "shell metacharacters are inert data" }`
      out.push({
        kind: 'http_chain',
        spec: {
          ...baseFields(env, 'Command injection via shell metacharacters (observed nonce proof)', 'CWE-78', 'injection-input', 'critical', jq),
          kind: 'http_chain',
          steps: [
            stepOf(env, 'c1', 'control', 'Benign value', control),
            stepOf(env, 'p1', 'probe', 'Observed metacharacter payload', observedProbe),
          ],
        },
      })
    }
  }
  return out
}

/**
 * Path traversal with a genuine out-of-jail oracle: the probe payload must return content that a
 * nonexistent sibling traversal cannot, or match a well-known file signature.
 */
export function synthTraversal(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'path_traversal_escape')
  if (!hit || !o.hyp.param) return []
  const param = o.hyp.param.name
  const location = o.hyp.location ?? 'query'
  const raw = String(hit.payload ?? '')
  if (!raw || raw.length > 200 || /[\r\n\0\\]/.test(raw)) return []
  const controlValue = `../guardian-none-${randomBytes(4).toString('hex')}.txt`
  const build = (value: string): RequestParts => {
    // Reuse the probe's injection encoding (query/form values are URL-encoded exactly once by the
    // broker), so the replay reproduces the payload the oracle actually accepted.
    if (location === 'query' || location === 'form') {
      const parts = requestParts(o, env, value)
      if (parts) return parts
    }
    return { method: o.hyp.method, pathAndQuery: o.hyp.endpoint.path, jsonBody: { [param]: value } }
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
    spec: {
      ...baseFields(env, 'Path traversal escapes the served root (jail-escape read)', 'CWE-22', 'path-traversal', 'high', jq),
      kind: 'http_chain',
      steps: [
        stepOf(env, 'c1', 'control', 'Nonexistent sibling traversal control', build(controlValue)),
        stepOf(env, 'p1', 'probe', 'Traversal payload that resolves outside the served root', build(raw)),
      ],
    },
  }]
}

export function synthSsti(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'expression_evaluated')
  if (!hit) return []
  const tpl = sstiTemplates[String(hit.engine)]
  const control = requestParts(o, env, 'guardian')
  const probe = tpl ? requestParts(o, env, tpl) : null
  if (!control || !probe) return []
  const spec = {
    ...baseFields(env, 'Server-side template injection (arithmetic evaluation)', 'CWE-1336', 'injection-input', 'high',
      '{ controlPassed: (.control.status < 500), confirmed: (.proof.mathVerified == true), observed: ("mathVerified=" + ((.proof.mathVerified // false) | tostring)), expected: "template input is not evaluated" }'),
    kind: 'rce_proof',
    proofMode: 'dynamic_math',
    requiresTier3Approval: true,
    controlStep: stepOf(env, 'c1', 'control', 'Benign value', control),
    probeStep: stepOf(env, 'p1', 'probe', 'Verifier-minted arithmetic expression', probe),
  }
  return [{ kind: 'rce_proof', spec }]
}
