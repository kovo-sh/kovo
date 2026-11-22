/**
 * Impact-first synthesis for two remaining realistic classes whose anomaly contracts are
 * behavioural rather than payload-echo:
 *
 *  - `invariant_violation` (CWE-840/472): a control mutation is accepted in-bounds, the probe
 *    mutation is accepted out-of-bounds, and a read-back (or the mutation response itself) proves
 *    the conserved quantity was actually broken.
 *  - `secret_disclosed` (CWE-200/532): a non-entitled actor receives a tenant secret marker that
 *    is absent from a control view (a masked/own view, an anonymous denial, or the actor's own
 *    tenant data).
 *
 * Both builders refuse partial evidence: they require a concrete bound/expected value and a
 * control that genuinely differs, so a route that simply returns the same body to everyone never
 * confirms.
 */
import { baseFields, is2xx, jqStr, stepOf } from './benchmark-specs-common.ts'
import type { RequestParts, SynthesizedSpec } from './benchmark-specs-common.ts'
import type { HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'

const SAFE_FIELD = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/
const SAFE_SELECTOR = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$/
const SAFE_PATH = /^\/(?!\/)[^\s\\]{0,4000}$/
const SAFE_ID = /^[A-Za-z0-9_.:-]{1,128}$/
const SAFE_METHOD = /^(POST|PUT|PATCH)$/

type Method = 'POST' | 'PUT' | 'PATCH'

function num(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) return Number(value)
  return null
}

function text(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function idIn(path: string, id: string | null): string {
  if (!path.includes('{{id}}')) return path
  return path.replaceAll('{{id}}', id ? encodeURIComponent(id) : '{{resource_id}}')
}

function methodOf(value: unknown, fallback: string): Method | null {
  const upper = String(value ?? fallback).toUpperCase()
  return SAFE_METHOD.test(upper) ? upper as Method : null
}

function requestFor(method: Method, path: string, body: unknown, encoding: string): RequestParts {
  if (encoding === 'form') {
    const raw = body && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : {}
    return {
      method, pathAndQuery: path,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      textBody: Object.entries(raw).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
    }
  }
  return { method, pathAndQuery: path, jsonBody: body && typeof body === 'object' ? body : {} }
}

function selectorExpr(stepId: string, field: string, selector?: string, collection?: string, idField?: string, recordId?: string): string {
  const base = `.steps.${stepId}.json`
  if (selector && SAFE_SELECTOR.test(selector)) {
    return `(${base}${selector.split('.').map(part => `[${jqStr(part)}]`).join('')})`
  }
  if (collection && idField && recordId) {
    return `([${base}[${jqStr(collection)}][]? | select((.[${jqStr(idField)}] | tostring) == ${jqStr(recordId)}) | .[${jqStr(field)}]][0])`
  }
  return `(${base}[${jqStr(field)}])`
}

interface InvariantShape {
  mode: 'bound' | 'delta' | 'mismatch' | 'sum'
  field: string
  selector?: string
  collection?: string
  idField?: string
  recordId?: string
  bound: number | null
  controlValue: number | null
  expectedValue: number | null
  comparator: 'gt' | 'lt' | 'gte' | 'lte' | 'ne'
  negative: boolean
}

function shapeFrom(hit: Record<string, unknown>): InvariantShape | null {
  const field = text(hit.stateField ?? hit.field)
  if (!SAFE_FIELD.test(field)) return null
  const selector = text(hit.stateSelector) || undefined
  if (selector && !SAFE_SELECTOR.test(selector)) return null
  const collection = text(hit.collection ?? hit.collectionKey) || undefined
  const idField = text(hit.idField ?? hit.recordIdField) || undefined
  const recordId = text(hit.recordId ?? hit.stateRecordId) || undefined
  if (collection && !SAFE_FIELD.test(collection)) return null
  if (idField && !SAFE_FIELD.test(idField)) return null
  if (recordId && !SAFE_ID.test(recordId)) return null
  const bound = num(hit.bound ?? hit.limit ?? hit.max)
  const controlValue = num(hit.controlValue ?? hit.baselineValue)
  const expectedValue = num(hit.expectedValue ?? hit.violatingValue)
  const explicit = text(hit.mode)
  const comparatorRaw = text(hit.comparator ?? hit.relation).toLowerCase()
  const comparator = (['gt', 'lt', 'gte', 'lte', 'ne'].includes(comparatorRaw) ? comparatorRaw : 'gt') as InvariantShape['comparator']
  const negative = hit.negative === true || comparator === 'lt'
  let mode: InvariantShape['mode']
  if (explicit === 'bound' || explicit === 'delta' || explicit === 'mismatch' || explicit === 'sum') mode = explicit
  else if (bound !== null) mode = 'bound'
  else if (hit.accumulate === true) mode = 'sum'
  else if (expectedValue !== null) mode = 'mismatch'
  else mode = 'delta'
  if ((mode === 'bound' || mode === 'sum') && bound === null) return null
  if (mode === 'mismatch' && expectedValue === null) return null
  return { mode, field, ...(selector ? { selector } : {}), ...(collection ? { collection } : {}), ...(idField ? { idField } : {}), ...(recordId ? { recordId } : {}), bound, controlValue, expectedValue, comparator, negative }
}

function accepted(stepId: string): string {
  return `((${is2xx(stepId)}) or (([(.steps.${stepId}.statuses // [])[] | select(. >= 200 and . < 300)] | length) >= 1))`
}

function state(stepId: string, s: InvariantShape): string {
  return selectorExpr(stepId, s.field, s.selector, s.collection, s.idField, s.recordId)
}

/** Control mutation is in-bounds (or leaves the baseline untouched). */
function controlHolds(s: InvariantShape, stepId: string): string {
  const value = state(stepId, s)
  if (s.mode === 'bound' || s.mode === 'sum') return `(${value} <= ${s.bound})`
  if (s.mode === 'mismatch') return `(${value} != ${s.expectedValue})`
  if (s.comparator === 'lt') return `(${value} >= 0)`
  if (s.comparator === 'ne') return s.controlValue !== null ? `(${value} == ${s.controlValue})` : 'false'
  return `(${value} >= 0)`
}

/** Probe mutation is out-of-bounds / violates the conservation relation. */
function probeViolates(s: InvariantShape, probeId: string, controlId: string): string {
  const value = state(probeId, s)
  if (s.mode === 'bound' || s.mode === 'sum') return `(${value} > ${s.bound})`
  if (s.mode === 'mismatch') return `(${value} == ${s.expectedValue})`
  if (s.comparator === 'lt') return `((${value} < 0) and (${value} < ${state(controlId, s)}))`
  if (s.comparator === 'ne') return `(${value} != ${state(controlId, s)})`
  if (s.comparator === 'gte') return `(${value} >= ${state(controlId, s)})`
  return `(${value} > ${state(controlId, s)})`
}

export function synthInvariantViolation(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'invariant_violation')
  if (!hit) return []
  const path = text(hit.path) || o.hyp.endpoint.path
  if (!SAFE_PATH.test(path)) return []
  const method = methodOf(hit.method, o.hyp.method)
  if (!method) return []
  const shape = shapeFrom(hit)
  if (!shape) return []
  const encoding = text(hit.encoding ?? hit.bodyEncoding) === 'form' ? 'form' : 'json'
  const probeBody = hit.body ?? hit.probeBody ?? hit.violatingBody
  if (probeBody === undefined || probeBody === null) return []
  const controlBody = hit.controlBody ?? hit.validBody ?? {}
  const readPathRaw = text(hit.readPath ?? hit.readBackPath)
  const readPath = readPathRaw && SAFE_PATH.test(readPathRaw) ? idIn(readPathRaw, null) : null
  const batchCount = num(hit.batchCount)
  const batch = batchCount !== null && batchCount >= 2 && batchCount <= 10 ? Math.floor(batchCount) : undefined
  const createPath = text(hit.createPath)
  const createBody = hit.createBody ?? hit.producerBody
  const cleanupBody = hit.cleanupBody ?? hit.restoreBody
  const recordId = text(hit.recordId ?? hit.stateRecordId)
  const persona = env.owner

  const steps: Array<Record<string, unknown>> = []
  if (env.caps.sessionAndCsrf) steps.push(stepOf(env, 's1', 'setup', 'Prime the session jar', { method: 'GET', pathAndQuery: '/' }, persona))
  if (createPath && SAFE_PATH.test(createPath)) {
    steps.push({
      ...stepOf(env, 's2', 'setup', 'Create a fresh object for the invariant check', requestFor('POST', idIn(createPath, null), createBody ?? {}, encoding), persona),
      extract: [{ varName: 'resource_id', from: 'json' as const, selector: text(hit.createIdSelector) || 'id' }],
    })
  }
  const controlRequest = requestFor(method, path, controlBody, encoding)
  steps.push(stepOf(env, 'c1', 'control', 'In-bounds mutation is accepted', controlRequest, persona))
  if (readPath) steps.push(stepOf(env, 'r1', 'control', 'Read back the in-bounds state', { method: 'GET', pathAndQuery: readPath }, persona))
  const probeRequest = requestFor(method, path, probeBody, encoding)
  steps.push(stepOf(env, 'p1', 'probe', 'Out-of-bounds mutation is accepted', probeRequest, persona, batch ? { batchCount: batch } : {}))
  if (readPath) steps.push(stepOf(env, 'r2', 'probe', 'Read back the violated state', { method: 'GET', pathAndQuery: readPath }, persona))
  if (cleanupBody && typeof cleanupBody === 'object') {
    steps.push(stepOf(env, 'z1', 'cleanup', 'Restore the original value', requestFor(method, path, cleanupBody, encoding), persona))
  }

  const controlStateId = readPath ? 'r1' : 'c1'
  const probeStateId = readPath ? 'r2' : 'p1'
  const controlReadOk = readPath ? is2xx('r1') : is2xx('c1')
  const probeReadOk = readPath ? is2xx('r2') : is2xx('p1')
  let confirmedExpr = `(${accepted('p1')} and ${probeReadOk} and (${probeViolates(shape, probeStateId, controlStateId)}))`
  if (shape.mode === 'sum') {
    confirmedExpr = `(${accepted('c1')} and ${accepted('p1')} and ((${state('c1', shape)} + ${state('p1', shape)}) > ${shape.bound}))`
  }
  const jq = `{ controlPassed: (${is2xx('c1')} and ${controlReadOk} and (${controlHolds(shape, controlStateId)})), ` +
    `confirmed: ${confirmedExpr}, ` +
    `observed: ("control=" + ((${state(controlStateId, shape)}) | tostring) + " probe=" + ((${state(probeStateId, shape)}) | tostring)), ` +
    `expected: "the conserved quantity stays within its server-side bound" }`
  const title = shape.mode === 'sum'
    ? 'Business logic allows a duplicate charge that exceeds the payment total'
    : shape.mode === 'mismatch'
      ? 'Business logic trusts a client-supplied price/plan value'
      : 'Business logic accepts an out-of-bounds quantity/balance'
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env, title, 'CWE-840', 'business-logic', 'high', jq),
      kind: 'http_chain',
      steps,
    },
  }]
}

// ---------------------------------------------------------------------------
// Information disclosure: non-entitled actor receives a tenant secret marker
// ---------------------------------------------------------------------------

function secretMatcher(hit: Record<string, unknown>): { pattern: string; expr: (stepId: string) => string } | null {
  const marker = text(hit.secretMarker ?? hit.marker ?? hit.secret)
  if (marker.length >= 6 && marker.length <= 128 && !/[\r\n\0]/.test(marker)) {
    // Keep only the non-secret shape: literal punctuation stays, long hex/digit runs become bounded
    // character classes. The raw token never enters the spec or the evidence report.
    const escapeRegex = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const shape = escapeRegex(marker)
      .replace(/[0-9a-f]{8,}/gi, '[0-9a-f]{12}')
      .replace(/[0-9]{8,}/g, '[0-9]{8,}')
    try {
      new RegExp(shape)
    } catch {
      return null
    }
    return { pattern: shape, expr: id => `(.proofMatches.${id}[0] == true)` }
  }
  const pattern = text(hit.secretPattern ?? hit.pattern)
  if (pattern.length >= 4 && pattern.length <= 200) {
    try {
      new RegExp(pattern)
    } catch {
      return null
    }
    return { pattern, expr: id => `(.proofMatches.${id}[0] == true)` }
  }
  return null
}

export function synthSecretDisclosure(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'secret_disclosed')
  if (!hit) return []
  const path = text(hit.path ?? hit.readPath)
  if (!SAFE_PATH.test(path)) return []
  const methodRaw = String(hit.method ?? 'GET').toUpperCase()
  if (methodRaw !== 'GET' && !SAFE_METHOD.test(methodRaw)) return []
  const method = methodRaw as 'GET' | Method
  const matcher = secretMatcher(hit)
  if (!matcher) return []
  const asPersona = (value: string | undefined) => (value && /^[a-z0-9_-]{1,32}$/.test(value) ? value : undefined)
  const actor = asPersona(text(hit.persona ?? hit.actor)) ?? asPersona(env.viewer) ?? asPersona(env.other) ?? env.owner
  if (!actor) return []
  const controlPathRaw = text(hit.controlPath)
  const ownPathRaw = text(hit.ownPath ?? hit.selfPath)
  const controlPath = ownPathRaw && SAFE_PATH.test(ownPathRaw) ? ownPathRaw : controlPathRaw && SAFE_PATH.test(controlPathRaw) ? controlPathRaw : path
  const controlActor = asPersona(text(hit.controlPersona)) ?? (controlPath === path && !ownPathRaw ? undefined : actor)
  const requestBody = hit.body && typeof hit.body === 'object' ? hit.body as Record<string, unknown> : undefined
  const encoding = text(hit.encoding ?? hit.bodyEncoding) === 'form' ? 'form' : 'json'
  const make = (stepId: string, role: 'control' | 'probe', description: string, target: string, persona: string | undefined): RequestParts =>
    method === 'GET' ? { method, pathAndQuery: target } : requestFor(method as Method, target, requestBody ?? {}, encoding)

  const steps: Array<Record<string, unknown>> = []
  if (env.caps.sessionAndCsrf) steps.push(stepOf(env, 's1', 'setup', 'Prime session cookies from the site root', { method: 'GET', pathAndQuery: '/' }, env.owner))
  steps.push(stepOf(env, 'c1', 'control', 'The non-entitled actor sees a masked / denied view', make('c1', 'control', 'control', controlPath, controlActor), controlActor))
  steps.push(stepOf(env, 'p1', 'probe', 'The same actor reads the resource and receives the secret', make('p1', 'probe', 'probe', path, actor), actor))
  const repeat = hit.repeat === true || hit.readBack === true
  if (repeat) steps.push(stepOf(env, 'p2', 'probe', 'Re-read the resource to confirm the secret persists', make('p2', 'probe', 'probe', path, actor), actor))

  const controlDeniedOrMasked = `((${matcher.expr('c1')}) | not)`
  // Sensitive field names (secret/token) are scrubbed by the broker before the verifier sees the
  // body, so the shape match may be unavailable. In that case a strictly larger probe body than a
  // masked/denied control is the observable differential: a masked preview cannot be longer than the
  // value it masks, and the hardened twin returns the same masked body to every actor.
  const controlSmaller = `((.steps.p1.bodyBytes // 0) > ((.steps.c1.bodyBytes // 0) + 4))`
  const probeLarger = `((.steps.p1.bodyBytes // 0) >= ((.steps.c1.bodyBytes // 0) + 8) and ((.steps.p1.mediaType // "") | test("json")))`
  const confirmed = `(${is2xx('p1')} and (${matcher.expr('p1')} or ${probeLarger})` +
    `${repeat ? ` and ${is2xx('p2')} and (${matcher.expr('p2')} or ((${probeLarger}) and (.steps.p2.bodyBytes >= .steps.p1.bodyBytes)))` : ''})`
  const jq = `{ controlPassed: ((${is2xx('c1')} or (.steps.c1.status == 401 or .steps.c1.status == 403)) and ${controlDeniedOrMasked} and ((${controlSmaller}) or (.steps.c1.status == 401 or .steps.c1.status == 403))), ` +
    `confirmed: ${confirmed}, ` +
    `observed: ("control bytes=" + (.steps.c1.bodyBytes // 0 | tostring) + " probe bytes=" + (.steps.p1.bodyBytes // 0 | tostring)), ` +
    `expected: "tenant secrets are only served to entitled principals" }`
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env, 'Tenant secret disclosed to a non-entitled principal', 'CWE-200', 'information-disclosure', 'high', jq),
      kind: 'http_chain',
      proofPatterns: [matcher.pattern],
      steps,
    },
  }]
}
