/**
 * v5 M3 synthesis contracts that await their probe anomaly shapes.
 *
 * Each builder is gated on an exact, documented anomaly type and refuses to fire on partial
 * evidence. They are safe to leave wired: until the probes emit these shapes the dispatcher never
 * reaches them (existing anomaly names do not collide). Unit tests exercise the contracts with
 * fixtures so the probe stream can land against a fixed target.
 *
 * NOTE: `write_path_bola` is a chain (cross-tenant write -> owner read-back -> cleanup) and
 * `csrf_state_change` relies on session/CSRF binding already supported by `ReplayStep.request`.
 * `webhook_signature_bypass` deliberately proves acceptance of an *unsigned/tampered* request; a
 * true HMAC re-signing replay needs verifier support (see report).
 */
import { baseFields, is2xx, jqStr, requestParts, stepOf } from './benchmark-specs-common.ts'
import type { RequestParts, SynthesizedSpec } from './benchmark-specs-common.ts'
import { fillPlaceholders, hasPathPlaceholder } from './benchmark-probes.ts'
import type { HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'

const SAFE_FIELD = /^[A-Za-z0-9_.[\]-]{1,64}$/
const SAFE_HEADER = /^[A-Za-z0-9-]{1,64}$/
const SAFE_STATE = /^[a-z0-9_-]{1,32}$/

function literal(value: unknown): string | null {
  if (typeof value === 'string') return jqStr(value)
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  if (typeof value === 'boolean') return String(value)
  return null
}

function fillId(path: string, id: string): string {
  return path.includes('{{id}}')
    ? path.replaceAll('{{id}}', encodeURIComponent(id))
    : hasPathPlaceholder(path) ? fillPlaceholders(path, encodeURIComponent(id)) : path
}

// ---------------------------------------------------------------------------
// CSRF: state-changing request accepted without the anti-CSRF token
// ---------------------------------------------------------------------------

export function synthCsrfStateChange(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'csrf_state_change')
  if (!hit) return []
  const path = String(hit.path ?? o.hyp.endpoint.path)
  const readPath = String(hit.readPath ?? '')
  const methodRaw = String(hit.method ?? 'POST').toUpperCase()
  const bodyField = String(hit.bodyField ?? '')
  const stateField = String(hit.stateField ?? '')
  const expectedLiteral = literal(hit.expectedValue)
  const controlLiteral = literal(hit.controlValue)
  if (!path.startsWith('/') || !readPath.startsWith('/')) return []
  if (!['POST', 'PUT', 'PATCH'].includes(methodRaw) || !SAFE_FIELD.test(bodyField) || !SAFE_FIELD.test(stateField)) return []
  if (!expectedLiteral || !controlLiteral || expectedLiteral === controlLiteral) return []
  const method = methodRaw as 'POST' | 'PUT' | 'PATCH'
  const write = (value: unknown): RequestParts => ({ method, pathAndQuery: path, jsonBody: { [bodyField]: value } })
  const jq = `{ controlPassed: (${is2xx('c1')}), ` +
    `confirmed: ((${is2xx('p1')}) and (${is2xx('p2')}) and (.steps.p2.json[${jqStr(stateField)}] == ${expectedLiteral})), ` +
    `observed: ("state=" + ((.steps.p2.json[${jqStr(stateField)}]) | tostring)), expected: "state change must require the anti-CSRF token" }`
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env, 'CSRF protection missing on a state-changing request', 'CWE-352', 'csrf', 'high', jq),
      kind: 'http_chain',
      steps: [
        stepOf(env, 'c1', 'control', 'State change with the anti-CSRF token bound', write(hit.controlValue), env.owner, env.caps.sessionAndCsrf ? { csrfBind: true } : {}),
        stepOf(env, 'p1', 'probe', 'Same state change without the anti-CSRF token', write(hit.expectedValue), env.owner),
        stepOf(env, 'p2', 'probe', 'Read the mutated state', { method: 'GET', pathAndQuery: readPath }, env.owner),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------
// Webhook signature: unsigned/tampered delivery accepted
// ---------------------------------------------------------------------------

export function synthWebhookSignature(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'webhook_signature_bypass')
  if (!hit) return []
  const path = String(hit.path ?? o.hyp.endpoint.path)
  const readPath = String(hit.readPath ?? '')
  const header = String(hit.headerName ?? '')
  const body = hit.body && typeof hit.body === 'object' && !Array.isArray(hit.body) ? hit.body as Record<string, unknown> : null
  const stateField = String(hit.stateField ?? '')
  const expectedLiteral = literal(hit.expectedValue)
  if (!path.startsWith('/') || !readPath.startsWith('/') || !body) return []
  if (!SAFE_HEADER.test(header) || /^(?:authorization|cookie|host)$/i.test(header) || !SAFE_FIELD.test(stateField) || !expectedLiteral) return []
  const jq = `{ controlPassed: (.steps.c1.status >= 400 and .steps.c1.status < 500), ` +
    `confirmed: ((${is2xx('p1')}) and (${is2xx('p2')}) and (.steps.p2.json[${jqStr(stateField)}] == ${expectedLiteral})), ` +
    `observed: ("unsigned status=" + (.steps.p1.status | tostring) + " state=" + ((.steps.p2.json[${jqStr(stateField)}]) | tostring)), expected: "unsigned webhook deliveries must be rejected" }`
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env, 'Webhook signature verification bypass (unsigned delivery accepted)', 'CWE-345', 'broken-authentication', 'high', jq),
      kind: 'http_chain',
      steps: [
        stepOf(env, 'c1', 'control', 'Tampered signature is rejected', { method: 'POST', pathAndQuery: path, headers: { [header]: 'guardian-invalid-signature' }, jsonBody: body }, null, {}, [400, 401, 403, 422]),
        stepOf(env, 'p1', 'probe', 'Same delivery unsigned is accepted', { method: 'POST', pathAndQuery: path, jsonBody: body }, null),
        stepOf(env, 'p2', 'probe', 'Read the delivery side effect', { method: 'GET', pathAndQuery: readPath }, env.owner),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------
// Open redirect: attacker-controlled redirect target honoured
// ---------------------------------------------------------------------------

export function synthOpenRedirect(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'open_redirect_differential')
  if (!hit) return []
  const payload = String(hit.payload ?? '')
  let observed: URL
  try { observed = new URL(String(hit.location ?? '')) } catch { return [] }
  if (!observed.hostname || /^(?:127\.|localhost$)/i.test(observed.hostname)) return []
  if (!payload || payload.length > 512 || /[\r\n\0]/.test(payload)) return []
  const control = requestParts(o, env, 'https://guardian-control.invalid/cb')
  const probe = requestParts(o, env, payload)
  if (!control || !probe) return []
  const host = observed.hostname.toLowerCase()
  if (!/^[a-z0-9.-]{4,253}$/.test(host)) return []
  const location = (id: string) => `((.steps.${id}.headers.location // .steps.${id}.headers.Location // "") | tostring)`
  const jq = `{ controlPassed: ((.steps.c1.status < 500) and ((${location('c1')}) | contains(${jqStr(host)}) | not)), ` +
    `confirmed: ((.steps.p1.status >= 300 and .steps.p1.status < 400) and ((${location('p1')}) | contains(${jqStr(host)}))), ` +
    `observed: ("redirect=" + (${location('p1')})), expected: "redirect targets stay on the registered origin" }`
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env, 'Open redirect via unvalidated redirect target', 'CWE-601', 'open-redirect', 'medium', jq),
      kind: 'http_chain',
      steps: [
        stepOf(env, 'c1', 'control', 'Unrelated control target', control),
        stepOf(env, 'p1', 'probe', 'Attacker-controlled redirect target', probe),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------
// Write-path BOLA: cross-tenant write, owner read-back, cleanup
// ---------------------------------------------------------------------------

export function synthWritePathBola(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'write_path_bola' || a.type === 'unauthorized_write')
  if (!hit || !env.owner || !env.other) return []
  const id = String(hit.resourceId ?? '')
  const readPath = String(hit.readPath ?? '')
  const stateField = String(hit.stateField ?? '')
  const expectedLiteral = literal(hit.expectedValue)
  const body = hit.writeBody && typeof hit.writeBody === 'object' && !Array.isArray(hit.writeBody) ? hit.writeBody as Record<string, unknown> : null
  const methodRaw = String(hit.method ?? 'PATCH').toUpperCase()
  if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(id) || !readPath.startsWith('/') || !SAFE_FIELD.test(stateField)) return []
  if (!expectedLiteral || !body || !['POST', 'PUT', 'PATCH'].includes(methodRaw)) return []
  const method = methodRaw as 'POST' | 'PUT' | 'PATCH'
  const target = fillId(String(hit.path ?? o.hyp.endpoint.path), id)
  const read = fillId(readPath, id)
  const cleanup = hit.cleanupBody && typeof hit.cleanupBody === 'object' && !Array.isArray(hit.cleanupBody) ? hit.cleanupBody as Record<string, unknown> : null
  const jq = `{ controlPassed: ((${is2xx('c1')}) and (.steps.c1.json[${jqStr(stateField)}] != ${expectedLiteral})), ` +
    `confirmed: ((${is2xx('p1')}) and (${is2xx('p2')}) and (.steps.p2.json[${jqStr(stateField)}] == ${expectedLiteral})), ` +
    `observed: ("owner read-back=" + ((.steps.p2.json[${jqStr(stateField)}]) | tostring)), expected: "non-owner writes must not mutate the object" }`
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env, 'Cross-tenant write (object-level authorization failure)', 'CWE-639', 'broken-access-control', 'high', jq),
      kind: 'http_chain',
      steps: [
        stepOf(env, 'c1', 'control', 'Owner reads the object before the write', { method: 'GET', pathAndQuery: read }, env.owner),
        stepOf(env, 'p1', 'probe', 'Non-owner writes to the object', { method, pathAndQuery: target, jsonBody: body }, env.other),
        stepOf(env, 'p2', 'probe', 'Owner reads the object back', { method: 'GET', pathAndQuery: read }, env.owner),
        ...(cleanup ? [stepOf(env, 'z1', 'cleanup', 'Restore the original object value', { method, pathAndQuery: target, jsonBody: cleanup }, env.owner)] : []),
      ],
    },
  }]
}

/** Dispatch only the v5 M3 anomaly contracts. */
export function synthM3Contracts(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  return [
    ...synthCsrfStateChange(o, env),
    ...synthWebhookSignature(o, env),
    ...synthOpenRedirect(o, env),
    ...synthWritePathBola(o, env),
  ]
}
