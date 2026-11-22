/** http_chain / rce_proof spec synthesis: authz, mass assignment, SSRF, XXE, SSTI. */
import { randomBytes } from 'node:crypto'
import { appendQuery, baseFields, is2xx, jqStr, requestParts, sameAsControl, stepOf } from './benchmark-specs-common.ts'
import type { RequestParts, SynthesizedSpec } from './benchmark-specs-common.ts'
import { fillPlaceholders, hasPathPlaceholder, probePathFor, siblingValue } from './benchmark-probes.ts'
import type { HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'

const canaryJq = (control: string) =>
  `{ controlPassed: (.steps.${control}.status < 500), confirmed: (.canary.triggered == true), observed: ("probeCallback=" + ((.canary.probeTriggered // false) | tostring)), expected: "no out-of-band callback" }`

export function synthAuthz(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const owner = o.pair?.owner ?? env.owner
  const other = o.pair?.other ?? env.other
  if (!owner || !other) return []
  const unauth = o.anomalies.filter(a => a.type === 'unauthorized_access')
  const otherHit = unauth.find(a => a.actor === 'other_persona')
  const anonHit = unauth.find(a => a.actor === 'anonymous')
  const method = String(otherHit?.method ?? anonHit?.method ?? 'GET')
  const mutating = method !== 'GET'
  const hit = otherHit ?? (mutating ? anonHit : undefined)
  if (!hit) return []
  const id = String(hit.resourceId)
  // A resource anonymous callers can read identically is public data, not an object-level authorization failure.
  const matrix = (o.details.matrix as Array<Record<string, unknown>> | undefined) ?? []
  if (!mutating && id && matrix.some(m => m.resourceId === id && m.actor === 'anonymous' && m.accessible === true)) return []
  const functionLevel = hit.functionLevel === true ||
    (!hasPathPlaceholder(o.hyp.endpoint.path) && !o.hyp.endpoint.params.some(p => (p.isObjectId || /(^|[_-])id$/i.test(p.name)) && p.location === 'query'))
  const path = functionLevel
    ? o.hyp.endpoint.path
    : hasPathPlaceholder(o.hyp.endpoint.path)
      ? fillPlaceholders(o.hyp.endpoint.path, encodeURIComponent(id))
      : `${o.hyp.endpoint.path}?${o.hyp.endpoint.params.find(p => p.location === 'query')?.name ?? 'id'}=${encodeURIComponent(id)}`
  const bodyTemplate = hit.bodyTemplate && typeof hit.bodyTemplate === 'object' ? hit.bodyTemplate : {}
  const parts: RequestParts = { method: method as RequestParts['method'], pathAndQuery: path, ...(mutating ? { jsonBody: bodyTemplate } : {}) }
  const probePersona = otherHit ? other : null
  // Negative control (object-level reads only): the identifier must actually select the object. A
  // random nonexistent id that yields the same owner representation means the route ignores the id
  // (self-service or sibling action), so the finding must not confirm.
  const negativeHit = !functionLevel && method === 'GET'
    ? (() => {
        const missing = `guardian-none-${randomBytes(5).toString('hex')}`
        const missingPath = hasPathPlaceholder(o.hyp.endpoint.path)
          ? fillPlaceholders(o.hyp.endpoint.path, encodeURIComponent(missing))
          : `${o.hyp.endpoint.path}?${o.hyp.endpoint.params.find(p => p.location === 'query')?.name ?? 'id'}=${encodeURIComponent(missing)}`
        return { missingPath }
      })()
    : null
  const negativeStep = negativeHit
    ? stepOf(env, 'c2', 'control', 'Owner requests a nonexistent identifier (must differ)', {
        method: 'GET', pathAndQuery: negativeHit.missingPath,
      }, owner, {}, [400, 403, 404])
    : null
  const negativeOk = negativeStep ? ` and ((.steps.c2.status >= 400) or (.steps.c2.body != .steps.c1.body))` : ''
  // Primary: the probe actor received at least every field/value the owner control received
  // (extra fields such as leak markers are expected). Fallback: byte/shape equality.
  const supersetJq = `{ controlPassed: (${is2xx('c1')}${negativeOk}), ` +
    `confirmed: (${is2xx('p1')} and (.steps.c1.json as $c | .steps.p1.json as $p | ` +
    `(([$c | keys[]] | length) > 0) and ` +
    `(([($c | to_entries[]) | select($p[.key] == .value)] | length) == ([$c | keys[]] | length)))), ` +
    `observed: ("status=" + (.steps.p1.status | tostring)), expected: "non-owner denied" }`
  const equalityJq = `{ controlPassed: (${is2xx('c1')}${negativeOk}), confirmed: (${is2xx('p1')} and ${sameAsControl('p1', 'c1')}), observed: ("status=" + (.steps.p1.status | tostring)), expected: "non-owner denied" }`
  const steps = [
    ...(negativeStep ? [negativeStep] : []),
    stepOf(env, 'c1', 'control', 'Authorized actor performs the request', parts, owner),
    stepOf(env, 'p1', 'probe', `${probePersona ? 'Lower-privileged actor' : 'Unauthenticated caller'} performs the same request`, parts, probePersona),
  ]
  return [
    { kind: 'http_chain', spec: { ...baseFields(env, 'Cross-actor object or function access', 'CWE-639', 'broken-access-control', 'high', supersetJq), kind: 'http_chain', steps } },
    { kind: 'http_chain', spec: { ...baseFields(env, 'Cross-actor object or function access', 'CWE-639', 'broken-access-control', 'high', equalityJq), kind: 'http_chain', steps } },
  ]
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
    pipe_echo: `${base} | echo {{nonce_part1}}$(echo {{nonce_part2}})`,
    backtick_echo: `${base}\`echo {{nonce_part1}}$(echo {{nonce_part2}})\``,
  }
  const template = templates[variant] ?? templates.semicolon_echo
  const control = requestParts(o, env, base)
  const probe = requestParts(o, env, template)
  if (!control || !probe) return []
  return [{
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
