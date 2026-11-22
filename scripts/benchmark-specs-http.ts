/** http_chain / rce_proof spec synthesis: authz, mass assignment, SSRF, XXE, SSTI. */
import { randomBytes } from 'node:crypto'
import { baseFields, is2xx, jqStr, requestParts, sameAsControl, stepOf } from './benchmark-specs-common.ts'
import type { RequestParts, SynthesizedSpec } from './benchmark-specs-common.ts'
import { fillPlaceholders, hasPathPlaceholder } from './benchmark-probes.ts'
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
  if (!mutating && matrix.some(m => m.resourceId === id && m.actor === 'anonymous' && m.accessible === true)) return []
  const path = hasPathPlaceholder(o.hyp.endpoint.path)
    ? fillPlaceholders(o.hyp.endpoint.path, encodeURIComponent(id))
    : `${o.hyp.endpoint.path}?${o.hyp.endpoint.params.find(p => p.location === 'query')?.name ?? 'id'}=${encodeURIComponent(id)}`
  const parts: RequestParts = { method: method as RequestParts['method'], pathAndQuery: path, ...(mutating ? { jsonBody: {} } : {}) }
  const probePersona = otherHit ? other : null
  // Primary: the probe actor received at least every field/value the owner control received
  // (extra fields such as leak markers are expected). Fallback: byte/shape equality.
  const supersetJq = `{ controlPassed: ${is2xx('c1')}, ` +
    `confirmed: (${is2xx('p1')} and (.steps.c1.json as $c | .steps.p1.json as $p | ` +
    `(([$c | keys[]] | length) > 0) and ` +
    `(([($c | to_entries[]) | select($p[.key] == .value)] | length) == ([$c | keys[]] | length)))), ` +
    `observed: ("status=" + (.steps.p1.status | tostring)), expected: "non-owner denied" }`
  const equalityJq = `{ controlPassed: ${is2xx('c1')}, confirmed: (${is2xx('p1')} and ${sameAsControl('p1', 'c1')}), observed: ("status=" + (.steps.p1.status | tostring)), expected: "non-owner denied" }`
  const steps = [
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

export function synthSsrf(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
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
