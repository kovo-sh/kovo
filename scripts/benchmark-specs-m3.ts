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
import { createHmac } from 'node:crypto'
import { baseFields, is2xx, jqStr, requestParts, stepOf } from './benchmark-specs-common.ts'
import type { RequestParts, SynthesizedSpec } from './benchmark-specs-common.ts'
import { synthInvariantViolation, synthSecretDisclosure } from './benchmark-specs-logic.ts'
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

const SAFE_SELECTOR = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$/

/** `.<path>` jq lookup for an explicit `stateSelector` anomaly field. */
function selectorPath(stepId: string, selector: string): string | null {
  if (!SAFE_SELECTOR.test(selector)) return null
  return `.steps.${stepId}.json${selector.split('.').map(part => `[${jqStr(part)}]`).join('')}`
}

/**
 * jq predicate for "the expected scalar exists on this step". Supports a top-level field, an
 * explicit selector, or a record inside a collection (`items[]`, `jobs[]`, ...). `recordId` narrows
 * the collection to the mutated object, so an unrelated row cannot satisfy the assertion.
 */
function stateExists(stepId: string, field: string, expectedLiteral: string, recordId: string | null, selector?: string, countMode = false): string {
  if (selector) {
    const path = selectorPath(stepId, selector)
    return path ? `(${path} == ${expectedLiteral})` : 'false'
  }
  const top = `(.steps.${stepId}.json[${jqStr(field)}] == ${expectedLiteral})`
  // Webhook counters expose an array and a minimum expected length rather than a scalar value.
  const topCount = countMode
    ? `(((.steps.${stepId}.json[${jqStr(field)}] | type) == "array") and (((.steps.${stepId}.json[${jqStr(field)}] | length) >= ${expectedLiteral})))`
    : 'false'
  const recordFilter = recordId
    ? ` | select([.[] | select((type == "string") or (type == "number")) | tostring] | index(${jqStr(recordId)}))`
    : ''
  const inCollection = `([.steps.${stepId}.json[]? | select(type == "array") | .[]? | select(type == "object")${recordFilter} | .[${jqStr(field)}]] | map(. == ${expectedLiteral}) | any)`
  return `((${top}) or (${topCount}) or (${inCollection}))`
}

/** Strict negation of `stateExists` (no top-level or collection record may already carry the value). */
function stateAbsent(stepId: string, field: string, expectedLiteral: string, recordId: string | null, selector?: string): string {
  if (selector) {
    const path = selectorPath(stepId, selector)
    return path ? `(${path} != ${expectedLiteral})` : 'false'
  }
  const top = `(.steps.${stepId}.json[${jqStr(field)}] != ${expectedLiteral})`
  const recordFilter = recordId
    ? ` | select([.[] | select((type == "string") or (type == "number")) | tostring] | index(${jqStr(recordId)}))`
    : ''
  const inCollection = `([.steps.${stepId}.json[]? | select(type == "array") | .[]? | select(type == "object")${recordFilter} | .[${jqStr(field)}]] | map(. == ${expectedLiteral}) | any)`
  return `((${top}) and ((${inCollection}) | not))`
}

/**
 * Record id for collection lookups. Prefer the probe's `stateRecordId`; otherwise use the most
 * id-shaped segment of the observed mutation path (e.g. `/jobs/job_ab12/trigger`).
 */
function deriveRecordId(hit: Record<string, unknown>): string | null {
  const explicit = hit.stateRecordId
  if (typeof explicit === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(explicit)) return explicit
  const segments = String(hit.path ?? '').split('?')[0].split('/').filter(Boolean)
  for (let i = segments.length - 1; i > 0; i -= 1) {
    const segment = segments[i]
    if (/^v\d+$/i.test(segment)) continue
    if (/^[A-Za-z0-9_.:-]{1,128}$/.test(segment) && /[\d_-]/.test(segment)) return segment
  }
  return null
}

/** `/api/v1/documents/{id}` -> `/api/v1/documents` (list route that may expose the record). */
function collectionPathFrom(template: string): string | null {
  const segments = template.split('?')[0].split('/').filter(Boolean)
  const index = segments.findIndex(segment => /^(?::[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\]|\{\{id\}\})$/.test(segment))
  if (index <= 0) return null
  return `/${segments.slice(0, index).join('/')}`
}

interface CsrfBody {
  headers: Record<string, string>
  jsonBody?: unknown
  textBody?: string
}

/**
 * CSRF mutation body in the encoding the probe observed (`bodyEncoding`), including action
 * envelopes `{field, value}` and raw `formBody`/`textBody` templates.
 */
function csrfBody(o: HypothesisOutcome, hit: Record<string, unknown>, bodyField: string, value: unknown): CsrfBody | null {
  if (typeof hit.textBody === 'string' && hit.textBody.length > 0) {
    const template = hit.textBody
    const replaced = template
      .replaceAll('{{value}}', encodeURIComponent(String(value)))
      .replaceAll('{{expectedValue}}', encodeURIComponent(String(value)))
    if (replaced === template) return null
    return { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, textBody: replaced }
  }
  const base: Record<string, unknown> = {}
  const rawForm = hit.formBody && typeof hit.formBody === 'object' && !Array.isArray(hit.formBody) ? hit.formBody as Record<string, unknown> : null
  if (rawForm) Object.assign(base, rawForm)
  const explicitWrite = hit.writeBody && typeof hit.writeBody === 'object' && !Array.isArray(hit.writeBody) ? hit.writeBody as Record<string, unknown> : null
  if (explicitWrite) Object.assign(base, explicitWrite)
  const hasEnvelope = 'field' in base && 'value' in base
  if (hasEnvelope) Object.assign(base, { field: bodyField, value })
  else if ('value' in base && !(bodyField in base)) Object.assign(base, { value })
  else Object.assign(base, { [bodyField]: value })
  // The probe's action-envelope hint is not always carried in the anomaly; infer it from the
  // endpoint parameters when the route exposes a `field`/`value` pair.
  const bodyParams = o.hyp.endpoint.params.filter(p => (p.location === 'json' || p.location === 'form') && !p.isCsrf)
  if (!rawForm && !explicitWrite && bodyParams.some(p => /^field$/i.test(p.name)) && bodyParams.some(p => /^value$/i.test(p.name))) {
    return { headers: { 'Content-Type': 'application/json' }, jsonBody: { field: bodyField, value } }
  }
  const encoding = hit.bodyEncoding === 'form' || rawForm ? 'form' : 'json'
  if (encoding === 'form') {
    return {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      textBody: Object.entries(base).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
    }
  }
  return { headers: { 'Content-Type': 'application/json' }, jsonBody: base }
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
  const stateSelector = typeof hit.stateSelector === 'string' ? hit.stateSelector : undefined
  const recordId = deriveRecordId(hit)
  if (process.env.GUARDIAN_BENCH_DEBUG === '1') {
    process.stderr.write(`[spec-csrf] path=${path} method=${methodRaw} bodyField=${bodyField} enc=${String(hit.bodyEncoding ?? '-')} readPath=${readPath} stateField=${stateField} control=${String(hit.controlValue ?? '-')} expected=${String(hit.expectedValue ?? '-')} recordId=${recordId ?? '-'} keys=${Object.keys(hit).join(',')}\n`)
  }
  if (!path.startsWith('/') || !readPath.startsWith('/')) return []
  if (!['POST', 'PUT', 'PATCH'].includes(methodRaw) || !SAFE_FIELD.test(bodyField) || !SAFE_FIELD.test(stateField)) return []
  if (!expectedLiteral || !controlLiteral || expectedLiteral === controlLiteral) return []
  if (stateSelector && !SAFE_SELECTOR.test(stateSelector)) return []
  const method = methodRaw as 'POST' | 'PUT' | 'PATCH'
  // Create-shaped CSRF: both the token-bound control and the tokenless probe create new objects;
  // each read-back addresses the id returned by that same create.
  if (hit.create === true && typeof hit.createReadTemplate === 'string' && hit.createReadTemplate.startsWith('/')) {
    const idSel = typeof hit.createIdSelector === 'string' && /^[A-Za-z_$][A-Za-z0-9_$.[\]-]{0,200}$/.test(hit.createIdSelector)
      ? hit.createIdSelector : 'id'
    const createReadTemplate = hit.createReadTemplate as string
    const readTpl = (varName: string) => createReadTemplate.replace(/:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\]/, `{{${varName}}}`)
    const encoding = hit.bodyEncoding === 'form' ? 'form' : 'json'
    const payloadFor = (value: unknown): CsrfBody => {
      const fields = /(?:amount|value|total|price|cents)/i.test(bodyField)
        ? ['amount', 'amount_cents', 'amountCents', 'value', 'cents', 'total', 'price']
        : [bodyField]
      const body = Object.fromEntries([...new Set(fields)].map(k => [k, value]))
      return encoding === 'form'
        ? { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, textBody: Object.entries(body).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&') }
        : { headers: { 'Content-Type': 'application/json' }, jsonBody: body }
    }
    const controlBody = payloadFor(hit.controlValue)
    const probeBody = payloadFor(hit.expectedValue)
    const foreign = { Origin: 'https://untrusted.invalid', Referer: 'https://untrusted.invalid/' }
    const steps: Array<Record<string, unknown>> = []
    if (env.caps.sessionAndCsrf) steps.push(stepOf(env, 's1', 'setup', 'Prime session cookies from the site root', { method: 'GET', pathAndQuery: '/' }, env.owner))
    steps.push({
      ...stepOf(env, 'c1', 'control', 'Create with the anti-CSRF token bound', {
        method, pathAndQuery: path, headers: controlBody.headers,
        ...(controlBody.jsonBody !== undefined ? { jsonBody: controlBody.jsonBody } : {}),
        ...(controlBody.textBody !== undefined ? { textBody: controlBody.textBody } : {}),
      }, env.owner, env.caps.sessionAndCsrf ? { csrfBind: true } : {}),
      extract: [{ varName: 'control_id', from: 'json' as const, selector: idSel }],
    })
    steps.push(stepOf(env, 'r1', 'control', 'Read the object created by the control', { method: 'GET', pathAndQuery: readTpl('control_id') }, env.owner))
    steps.push({
      ...stepOf(env, 'p1', 'probe', 'Same create without the anti-CSRF token (foreign Origin)', {
        method, pathAndQuery: path, headers: { ...probeBody.headers, ...foreign },
        ...(probeBody.jsonBody !== undefined ? { jsonBody: probeBody.jsonBody } : {}),
        ...(probeBody.textBody !== undefined ? { textBody: probeBody.textBody } : {}),
      }, env.owner),
      extract: [{ varName: 'probe_id', from: 'json' as const, selector: idSel }],
    })
    steps.push(stepOf(env, 'p2', 'probe', 'Read the object created by the tokenless request', { method: 'GET', pathAndQuery: readTpl('probe_id') }, env.owner))
    const stateEq = (id: string, value: string) => `(((.steps.${id}.json[${jqStr(stateField)}] // "") | tostring | ascii_downcase) == ${jqStr(value.toLowerCase())})`
    const jq = `{ controlPassed: ((${is2xx('c1')}) and (${is2xx('r1')}) and ${stateEq('r1', String(hit.controlValue))}), ` +
      `confirmed: ((${is2xx('p1')}) and (${is2xx('p2')}) and ${stateEq('p2', String(hit.expectedValue))}), ` +
      `observed: ("control=" + ((.steps.r1.json[${jqStr(stateField)}] // "?") | tostring) + " probe=" + ((.steps.p2.json[${jqStr(stateField)}] // "?") | tostring)), ` +
      'expected: "state-changing creates must require the anti-CSRF token" }'
    return [{
      kind: 'http_chain',
      spec: {
        ...baseFields(env, 'CSRF protection missing on a create-shaped request', 'CWE-352', 'csrf', 'high', jq),
        kind: 'http_chain',
        steps,
      },
    }]
  }
  const controlBody = csrfBody(o, hit, bodyField, hit.controlValue)
  const probeBody = csrfBody(o, hit, bodyField, hit.expectedValue)
  if (!controlBody || !probeBody) return []
  const read: RequestParts = { method: 'GET', pathAndQuery: readPath }
  const foreign = { Origin: 'https://untrusted.invalid', Referer: 'https://untrusted.invalid/' }
  const jq = `{ controlPassed: ((${is2xx('c1')}) and (${is2xx('r1')}) and ((${stateExists('r1', stateField, controlLiteral, recordId, stateSelector)}) or (${stateExists('r1', stateField, expectedLiteral, recordId, stateSelector)}))), ` +
    `confirmed: ((${is2xx('p1')}) and (${is2xx('p2')}) and (${stateExists('p2', stateField, expectedLiteral, recordId, stateSelector)})), ` +
    `observed: ("state=" + ((.steps.p2.json[${jqStr(stateField)}] // "collection") | tostring)), expected: "state change must require the anti-CSRF token" }`
  const steps: Array<Record<string, unknown>> = []
  if (env.caps.sessionAndCsrf) {
    steps.push(stepOf(env, 's1', 'setup', 'Prime session cookies from the site root', { method: 'GET', pathAndQuery: '/' }, env.owner))
    steps.push(stepOf(env, 's2', 'setup', 'Load the state page so the jar binds its anti-CSRF token', read, env.owner))
  }
  steps.push(stepOf(env, 'c1', 'control', 'State change with the anti-CSRF token bound', {
    method, pathAndQuery: path, headers: controlBody.headers,
    ...(controlBody.jsonBody !== undefined ? { jsonBody: controlBody.jsonBody } : {}),
    ...(controlBody.textBody !== undefined ? { textBody: controlBody.textBody } : {}),
  }, env.owner, env.caps.sessionAndCsrf ? { csrfBind: true } : {}))
  steps.push(stepOf(env, 'r1', 'control', 'Read the restored baseline state', read, env.owner))
  steps.push(stepOf(env, 'p1', 'probe', 'Same state change without the anti-CSRF token (foreign Origin)', {
    method, pathAndQuery: path, headers: { ...probeBody.headers, ...foreign },
    ...(probeBody.jsonBody !== undefined ? { jsonBody: probeBody.jsonBody } : {}),
    ...(probeBody.textBody !== undefined ? { textBody: probeBody.textBody } : {}),
  }, env.owner))
  steps.push(stepOf(env, 'p2', 'probe', 'Read the mutated state', read, env.owner))
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env, 'CSRF protection missing on a state-changing request', 'CWE-352', 'csrf', 'high', jq),
      kind: 'http_chain',
      steps,
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
  const acceptance = hit.proof === 'acceptance'
  // A POST to the same path as the delivery/list read is a CRUD create, not a signed inbound
  // receiver; only an explicit processing acknowledgement may confirm that ambiguous shape.
  if (!acceptance && readPath && readPath === path) return []
  if (process.env.GUARDIAN_BENCH_DEBUG === '1') {
    process.stderr.write(`[spec-webhook] path=${path} variant=${String(hit.variant ?? '-')} proof=${String(hit.proof ?? '-')} header=${header || '-'} bodyKeys=${body ? Object.keys(body).join(',') : 'none'} readPath=${readPath || '-'} stateField=${String(hit.stateField ?? '-')} expected=${String(hit.expectedValue ?? '-')}\n`)
  }
  if (!path.startsWith('/') || !body) return []
  if (!SAFE_HEADER.test(header) || /^(?:authorization|cookie|host)$/i.test(header)) return []
  if (!acceptance && (!readPath.startsWith('/') || !SAFE_FIELD.test(stateField) || !expectedLiteral)) return []
  const inline = /^inline_key:([A-Za-z0-9_]+)\/([A-Za-z0-9_]+)$/.exec(String(hit.variant ?? ''))
  const inlineSig = inline && body ? inlineSignaturePlan(body, inline[1], inline[2], String(hit.timestampField ?? 'ts')) : null
  const control = () => {
    // Self-signed deliveries carry the signing key and signature *inside* the body; a header-only
    // tamper would leave the inline signature valid and turn the control into another acceptance.
    if (inline) {
      return stepOf(env, 'c1', 'control', 'Tampered inline signature is rejected', {
        method: 'POST', pathAndQuery: path, headers: { 'Content-Type': 'application/json' }, jsonBody: { ...body, [inline[2]]: 'guardian-invalid-signature' },
      }, null, {}, [400, 401, 403, 422])
    }
    return stepOf(env, 'c1', 'control', 'Tampered signature is rejected', {
      method: 'POST', pathAndQuery: path, headers: { 'Content-Type': 'application/json', [header]: 'guardian-invalid-signature' }, jsonBody: body,
    }, null, {}, [400, 401, 403, 422])
  }
  const probeStep = (id: string, role: 'control' | 'probe', description: string, withSignature: boolean) => {
    const parts: RequestParts = {
      method: 'POST', pathAndQuery: path, headers: { 'Content-Type': 'application/json' }, jsonBody: body,
    }
    const extra: Record<string, unknown> = {}
    if (withSignature && inlineSig) {
      const eventField = typeof body.event === 'object' ? 'event' : typeof body.payload === 'object' ? 'payload' : undefined
      extra.bodySignature = {
        keyField: inlineSig.keyField,
        signatureField: inlineSig.signatureField,
        timestampField: inlineSig.timestampField,
        ...(eventField ? { eventField } : {}),
        canonical: inlineSig.canonical,
        encoding: inlineSig.encoding,
      }
    }
    return stepOf(env, id, role, description, parts, null, extra)
  }
  const signatureTitle = inlineSig
    ? 'Webhook trusts an attacker-supplied inline signing key (self-signed delivery accepted)'
    : 'Webhook signature verification bypass (unsigned delivery accepted)'
  if (acceptance) {
    // No delivery read route: the receiver's explicit processing acknowledgement plus a rejected
    // tampered control is the evidence (matches the probe's acceptance proof).
    const ack = '(((.steps.p1.body // "") | tostring) | test("\\"(?:ok|received|processed|accepted|success)\\"\\\\s*:\\\\s*true"; "i"))'
    const jq = `{ controlPassed: (.steps.c1.status >= 400 and .steps.c1.status < 500), ` +
      `confirmed: ((.steps.c1.status >= 400 and .steps.c1.status < 500) and (${is2xx('p1')}) and (${ack})), ` +
      `observed: ("forged status=" + (.steps.p1.status | tostring)), expected: "webhook deliveries must be signed with the endpoint secret" }`
    return [{
      kind: 'http_chain',
      spec: {
        ...baseFields(env, signatureTitle, 'CWE-345', 'broken-authentication', 'high', jq),
        kind: 'http_chain',
        steps: [
          control(),
          probeStep('p1', 'probe', 'Same delivery self-signed with an attacker key is processed', true),
        ],
      },
    }]
  }
  const jq = `{ controlPassed: (.steps.c1.status >= 400 and .steps.c1.status < 500), ` +
    `confirmed: ((.steps.c1.status >= 400 and .steps.c1.status < 500) and (${is2xx('p1')}) and (${is2xx('p2')}) and (${stateExists('p2', stateField, expectedLiteral!, deriveRecordId({ ...hit, path: readPath }), typeof hit.stateSelector === 'string' ? hit.stateSelector : undefined, typeof hit.expectedValue === 'number')})), ` +
    `observed: ("forged status=" + (.steps.p1.status | tostring) + " state=" + ((.steps.p2.json[${jqStr(stateField)}]) | tostring)), expected: "webhook deliveries must be signed with the endpoint secret" }`
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env, signatureTitle, 'CWE-345', 'broken-authentication', 'high', jq),
      kind: 'http_chain',
      steps: [
        control(),
        probeStep('p1', 'probe', 'Same delivery self-signed with an attacker key is accepted', true),
        stepOf(env, 'p2', 'probe', 'Read the delivery side effect', { method: 'GET', pathAndQuery: readPath }, env.owner),
      ],
    },
  }]
}

/**
 * Identify which documented canonical form the probe's accepted inline signature used by
 * recomputing the HMAC with the attacker key the probe itself placed in the body. The replayed
 * delivery then mints a fresh key + timestamp for the same canonical form.
 */
function inlineSignaturePlan(
  body: Record<string, unknown>, keyField: string, signatureField: string, timestampField: string,
): { keyField: string; signatureField: string; timestampField: string; canonical: 'ts_event' | 'ts_body' | 'event' | 'body'; encoding: 'hex' | 'base64' } | null {
  const key = body[keyField]
  const signature = body[signatureField]
  if (typeof key !== 'string' || typeof signature !== 'string' || !key || !signature) return null
  const ts = String(body[timestampField] ?? '')
  const withoutSig: Record<string, unknown> = { ...body }
  delete withoutSig[signatureField]
  const event = withoutSig.event ?? withoutSig.payload ?? withoutSig.data ?? withoutSig
  const asText = (value: unknown): string => (typeof value === 'string' ? value : JSON.stringify(value))
  const candidates: Array<{ canonical: 'ts_event' | 'ts_body' | 'event' | 'body'; value: string }> = [
    { canonical: 'ts_event', value: `${ts}.${asText(event)}` },
    { canonical: 'ts_body', value: `${ts}.${JSON.stringify(withoutSig)}` },
    { canonical: 'event', value: asText(event) },
    { canonical: 'body', value: JSON.stringify(withoutSig) },
  ]
  for (const candidate of candidates) {
    for (const encoding of ['hex', 'base64'] as const) {
      if (createHmac('sha256', key).update(candidate.value).digest(encoding) === signature) {
        return { keyField, signatureField, timestampField, canonical: candidate.canonical, encoding }
      }
    }
  }
  return null
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
  const detailRead = String(hit.readPath ?? '')
  const stateField = String(hit.stateField ?? '')
  const expectedLiteral = literal(hit.expectedValue)
  const body = hit.writeBody && typeof hit.writeBody === 'object' && !Array.isArray(hit.writeBody) ? hit.writeBody as Record<string, unknown> : null
  const methodRaw = String(hit.method ?? 'PATCH').toUpperCase()
  if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(id) || !SAFE_FIELD.test(stateField)) return []
  if (!expectedLiteral || !body || !['POST', 'PUT', 'PATCH'].includes(methodRaw)) return []
  const method = methodRaw as 'POST' | 'PUT' | 'PATCH'
  const targetTemplate = String(hit.path ?? o.hyp.endpoint.path)
  const target = fillId(targetTemplate, id)
  const cleanup = hit.cleanupBody && typeof hit.cleanupBody === 'object' && !Array.isArray(hit.cleanupBody) ? hit.cleanupBody as Record<string, unknown> : null
  const selector = typeof hit.stateSelector === 'string' ? hit.stateSelector : undefined
  if (selector && !SAFE_SELECTOR.test(selector)) return []
  // The anomaly's resourceId is the exact object the probe mutated; only fall back to path parsing
  // when the probe did not carry one.
  const recordId = typeof hit.stateRecordId === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(hit.stateRecordId)
    ? hit.stateRecordId
    : id

  const listTemplateRaw = typeof hit.listReadPath === 'string' ? hit.listReadPath
    : typeof hit.readListPath === 'string' ? hit.readListPath
      : typeof hit.collectionPath === 'string' ? hit.collectionPath
        : collectionPathFrom(detailRead || targetTemplate)
  const reads: Array<{ label: string; path: string; id: string }> = []
  if (detailRead.startsWith('/')) reads.push({ label: 'detail', path: fillId(detailRead, id), id: recordId })
  if (listTemplateRaw && listTemplateRaw.startsWith('/')) {
    const listPath = fillId(listTemplateRaw, id)
    if (!reads.some(r => r.path === listPath)) reads.push({ label: 'list', path: listPath, id: recordId })
  }
  if (reads.length === 0) return []

  return reads.map(({ label, path: read, id: lookupId }) => {
    const jq = `{ controlPassed: ((${is2xx('c1')}) and (${stateAbsent('c1', stateField, expectedLiteral, lookupId, selector)})), ` +
      `confirmed: ((${is2xx('p1')}) and (${is2xx('p2')}) and (${stateExists('p2', stateField, expectedLiteral, lookupId, selector)})), ` +
      `observed: ("owner ${label} read-back=" + ((.steps.p2.json[${jqStr(stateField)}] // "collection") | tostring)), expected: "non-owner writes must not mutate the object" }`
    return {
      kind: 'http_chain',
      spec: {
        ...baseFields(env, 'Cross-tenant write (object-level authorization failure)', 'CWE-639', 'broken-access-control', 'high', jq),
        kind: 'http_chain',
        steps: [
          stepOf(env, 'c1', 'control', `Owner reads the ${label} view before the write`, { method: 'GET', pathAndQuery: read }, env.owner),
          stepOf(env, 'p1', 'probe', 'Non-owner writes to the object', { method, pathAndQuery: target, jsonBody: body }, env.other),
          stepOf(env, 'p2', 'probe', `Owner reads the ${label} view back`, { method: 'GET', pathAndQuery: read }, env.owner),
          ...(cleanup ? [stepOf(env, 'z1', 'cleanup', 'Restore the original object value', { method, pathAndQuery: target, jsonBody: cleanup }, env.owner)] : []),
        ],
      },
    }
  })
}

/** Dispatch only the v5 M3 anomaly contracts. */
export function synthM3Contracts(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  return [
    ...synthInvariantViolation(o, env),
    ...synthSecretDisclosure(o, env),
    ...synthCsrfStateChange(o, env),
    ...synthWebhookSignature(o, env),
    ...synthOpenRedirect(o, env),
    ...synthWritePathBola(o, env),
  ]
}
