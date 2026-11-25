// Probe family module — implementation moved verbatim from surface-engine.ts (no behavior change).
import type { BrokerExchangeResult } from '.././broker.ts'
import { jsonRecord, randToken, scalarMatches, stateValueCandidate, stateViewOf } from './context.ts'
import type { DiffContext, DiffOutcome, ProbeDifferentialRequest } from './context.ts'
import type { ProbeModule } from './registry.ts'



/** Replace `:name` / `{name}` / `[name]` path segments (last one wins) inside a template. */
export function fillPathTemplate(template: string, value: string): string {
  const segs = template.split('?')
  const parts = segs[0]!.split('/')
  let last = -1
  parts.forEach((s, i) => { if (/^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/.test(s)) last = i })
  const filled = parts.map((s, i) => (/^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/.test(s) ? (i === last ? value : '1') : s)).join('/')
  return segs.length > 1 ? `${filled}?${segs.slice(1).join('?')}` : filled
}



/** First id-shaped scalar in a create response (request-derived, never a benchmark constant). */
export function extractCreatedId(body: string): string | null {
  try {
    const parsed = JSON.parse(body) as unknown
    const scan = (node: unknown, depth: number): string | null => {
      if (depth > 4 || node === null || node === undefined) return null
      if (Array.isArray(node)) {
        for (const item of node.slice(0, 3)) { const hit = scan(item, depth + 1); if (hit) return hit }
        return null
      }
      if (typeof node !== 'object') return null
      const rec = node as Record<string, unknown>
      for (const key of ['id', 'external_id', 'externalId', 'uuid', 'ref']) {
        const v = rec[key]
        if ((typeof v === 'string' || typeof v === 'number') && /^[A-Za-z0-9_.:-]{1,128}$/.test(String(v))) return String(v)
      }
      for (const v of Object.values(rec)) { const hit = scan(v, depth + 1); if (hit) return hit }
      return null
    }
    return scan(parsed, 0)
  } catch { return null }
}



/**
 * Create-shaped CSRF proof: a tokenless cross-origin create is replayed, then the object the API just
 * returned is read back through its own detail route. The token-bound control uses a different value,
 * so the same read route must not carry the probe value.
 */
export async function diffCsrfCreate(
  ctx: DiffContext,
  readCandidates: string[],
  req: ProbeDifferentialRequest,
  method: 'POST' | 'PUT' | 'PATCH',
): Promise<DiffOutcome> {
  const { send, anomalies } = ctx
  const template = req.createReadTemplate
  if (!template) {
    return { verdict: 'inconclusive', summary: 'No readable state field was found on the candidate read routes.', details: {} }
  }
  const bodyField = req.bodyField ?? req.stateField ?? 'amount'
  const numeric = /(?:amount|value|total|price|qty|quantity|count|number|balance)/i.test(bodyField)
  const expectedValue: string = String(req.expectedValue ?? (numeric ? 120_000 + Math.floor(Math.random() * 700_000) : `kovo_state_${randToken(8)}`))
  const controlValue: string = String(req.controlValue ?? (numeric ? Math.max(1, Number(expectedValue) - 1) : `kovo_control_${randToken(8)}`))
  if (String(expectedValue) === String(controlValue)) {
    return { verdict: 'no_signal', summary: 'Create differential values collided.', details: {} }
  }
  const foreignOrigin = req.foreignOrigin ?? 'https://untrusted.invalid'
  const fieldAliases = (field: string): string[] => {
    if (/(?:amount|value|total|price|cents)/i.test(field)) return [...new Set([field, 'amount', 'amount_cents', 'amountCents', 'value', 'cents', 'total', 'price'])]
    return [...new Set([field, 'status', 'state', 'name', 'title', 'value'])]
  }
  const encodeBody = (value: unknown, encoding: 'json' | 'form'): { headers: Record<string, string>; body: string } => {
    let payload: Record<string, unknown>
    if (req.writeBody) {
      payload = 'field' in req.writeBody ? { ...req.writeBody, field: bodyField, value } : { ...req.writeBody, [bodyField]: value }
    } else {
      // The write field name may not have been exposed by recon; populate the semantic aliases the
      // route vocabulary uses so the created object carries the marker in whichever field it reads.
      payload = {}
      for (const name of fieldAliases(bodyField)) payload[name] = value
    }
    if (encoding === 'form') {
      return {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: Object.entries(payload).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
      }
    }
    return { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }
  }
  const readView = (body: string, field: string): unknown => {
    const rec = jsonRecord(body)
    if (!rec) return undefined
    if (field in rec && typeof rec[field] !== 'object') return rec[field]
    for (const v of Object.values(rec)) {
      if (!Array.isArray(v)) continue
      for (const row of v) {
        if (row && typeof row === 'object' && field in (row as Record<string, unknown>)) return (row as Record<string, unknown>)[field]
      }
    }
    return undefined
  }
  const carriesValue = (body: string, value: unknown): boolean => {
    const rec = jsonRecord(body)
    if (!rec) return false
    const walk = (node: unknown, depth: number): boolean => {
      if (depth > 4 || node === null || node === undefined) return false
      if (Array.isArray(node)) return node.slice(0, 30).some(v => walk(v, depth + 1))
      if (typeof node === 'object') return Object.values(node as Record<string, unknown>).some(v => walk(v, depth + 1))
      return (typeof node === 'string' || typeof node === 'number') && String(node) === String(value)
    }
    return walk(rec, 0)
  }
  const encodings = req.bodyEncodings?.length ? req.bodyEncodings : (['form', 'json'] as const)
  let probeStatus: number | null = null
  let probeReadStatus: number | null = null
  let probeId: string | null = null
  let encoding: 'json' | 'form' | null = null
  let stateField = req.stateField ?? bodyField
  for (const enc of encodings) {
    const encoded = encodeBody(expectedValue, enc)
    const write = await send({
      method, pathAndQuery: req.pathAndQuery,
      headers: { ...encoded.headers, Origin: foreignOrigin, Referer: `${foreignOrigin}/` },
      body: encoded.body,
    })
    probeStatus = write?.status ?? null
    if (!write || write.status < 200 || write.status >= 300) continue
    const id = extractCreatedId(write.body)
    if (!id) continue
    const readPath = fillPathTemplate(template, encodeURIComponent(id))
    const read = await send({ method: 'GET', pathAndQuery: readPath })
    probeReadStatus = read?.status ?? null
    if (!read || read.status < 200 || read.status >= 300) continue
    const actual = readView(read.body, stateField)
    if (actual !== undefined && String(actual) === String(expectedValue)) {
      probeId = id
      encoding = enc
      break
    }
    // Field name may differ on the detail view; accept the marker anywhere in the created object.
    if (carriesValue(read.body, expectedValue)) {
      probeId = id
      encoding = enc
      break
    }
  }
  if (!probeId || !encoding) {
    return {
      verdict: 'no_signal',
      summary: 'The tokenless cross-origin create was rejected or its created object could not be read back.',
      details: { probeStatus, probeReadStatus, expectedValue, bodyField },
    }
  }
  const controlEncoded = encodeBody(controlValue, encoding)
  const controlWrite = await send({
    method, pathAndQuery: req.pathAndQuery,
    headers: { ...controlEncoded.headers, Origin: req.origin, Referer: `${req.origin}/` },
    body: controlEncoded.body,
    csrfBind: true,
  })
  let controlReadStatus: number | null = null
  let controlValueSeen: unknown
  const controlId = controlWrite && controlWrite.status >= 200 && controlWrite.status < 300 ? extractCreatedId(controlWrite.body) : null
  if (controlId) {
    const read = await send({ method: 'GET', pathAndQuery: fillPathTemplate(template, encodeURIComponent(controlId)) })
    controlReadStatus = read?.status ?? null
    if (read) controlValueSeen = readView(read.body, stateField)
  }
  const controlOk = Boolean(controlId && controlReadStatus && controlReadStatus >= 200 && controlReadStatus < 300 &&
    controlValueSeen !== undefined && String(controlValueSeen) === String(controlValue))
  const details = {
    create: true, bodyField, stateField, expectedValue, controlValue, probeStatus, probeReadStatus,
    controlStatus: controlWrite?.status ?? null, controlReadStatus, controlValueSeen, encoding,
    probeId, controlId, controlOk,
  }
  if (!controlOk) {
    return { verdict: 'no_signal', summary: 'The token-bound control create could not be read back, so the create differential is unstable.', details }
  }
  anomalies.push({
    type: 'csrf_state_change',
    path: req.pathAndQuery,
    method,
    bodyField,
    readPath: fillPathTemplate(template, encodeURIComponent(probeId)),
    stateField,
    controlValue,
    expectedValue,
    bodyEncoding: encoding,
    stateRecordId: probeId,
    create: true,
    createReadTemplate: template,
    createIdSelector: 'id',
  })
  return {
    verdict: 'signal',
    summary: 'A cookie-authenticated create succeeded without the anti-CSRF token and the created object was read back with the probe value.',
    details,
  }
}



/**
 * CSRF state-change differential (CWE-352).
 *
 * A cookie-authenticated mutation is replayed with only the victim session (no anti-CSRF token and
 * a foreign Origin), then the documented read route must show the new value. A same-origin control
 * write with the session's token restores the baseline (and proves the endpoint is functional), so a
 * 200 that never mutates or a token-enforcing endpoint both stay silent.
 */
export async function diffCsrfStateChange(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const method: 'POST' | 'PUT' | 'PATCH' =
    req.method === 'PUT' || req.method === 'PATCH' ? req.method : 'POST'
  const readPath = req.readPath
  if (!readPath && !req.createReadTemplate) return { verdict: 'inconclusive', summary: 'csrf_state_change needs a read path.', details: {} }
  if (!req.session) return { verdict: 'inconclusive', summary: 'csrf_state_change needs a bound session.', details: {} }

  // Visit token-issuing routes first so the broker jar can bind the session's anti-CSRF token.
  const readCandidates = [...new Set([...(readPath ? [readPath] : []), ...(req.readPathCandidates ?? [])])].slice(0, 4)
  const primes = [...new Set([...(req.csrfPrimePaths ?? []), ...readCandidates, '/'])].slice(0, 5)
  for (const path of primes) {
    if (ctx.runner.stopReason) break
    await send({ method: 'GET', pathAndQuery: path })
  }

  let effectiveReadPath = readPath
  let baseline: BrokerExchangeResult | null = null
  let baselineView: { field: string; value: unknown } | null = null
  for (const path of readCandidates) {
    const ex = await send({ method: 'GET', pathAndQuery: path })
    if (!ex || ex.status < 200 || ex.status >= 300) continue
    const view = stateViewOf(jsonRecord(ex.body), req.stateField, req.stateRecordId)
    if (!view) continue
    effectiveReadPath = path
    baseline = ex
    baselineView = view
    break
  }
  if (!baseline || !baselineView) {
    return await diffCsrfCreate(ctx, readCandidates, req, method)
  }
  const stateField = baselineView.field
  const baselineValue = baselineView.value
  const readPathResolved: string = effectiveReadPath ?? readPath ?? req.createReadTemplate ?? ''
  const controlValue = req.controlValue ?? baselineValue
  let expectedValue = req.expectedValue ?? stateValueCandidate(baselineValue, stateField)
  if (scalarMatches(controlValue, expectedValue)) {
    return { verdict: 'no_signal', summary: 'Control and expected state values are identical; nothing to differentiate.', details: {} }
  }
  const bodyField = req.bodyField ?? stateField
  const writeBody = (value: unknown): Record<string, unknown> => {
    if (req.writeBody) {
      if ('field' in req.writeBody) return { ...req.writeBody, field: bodyField, value }
      return { ...req.writeBody, [bodyField]: value }
    }
    return { [bodyField]: value }
  }
  const foreignOrigin = req.foreignOrigin ?? 'https://untrusted.invalid'
  const encodeBody = (value: unknown, encoding: 'json' | 'form'): { headers: Record<string, string>; body: string } => {
    const payload = writeBody(value)
    if (encoding === 'form') {
      return {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: Object.entries(payload).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
      }
    }
    return { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }
  }

  let probeWrite: BrokerExchangeResult | null = null
  let probeRead: BrokerExchangeResult | null = null
  let mutationEncoding: 'json' | 'form' | null = null
  const encodings = req.bodyEncodings?.length ? req.bodyEncodings : (['json', 'form'] as const)
  for (const encoding of encodings) {
    const encoded = encodeBody(expectedValue, encoding)
    probeWrite = await send({
      method,
      pathAndQuery: req.pathAndQuery,
      headers: { ...encoded.headers, Origin: foreignOrigin, Referer: `${foreignOrigin}/` },
      body: encoded.body,
    })
    if (!probeWrite || probeWrite.status < 200 || probeWrite.status >= 300) continue
    probeRead = await send({ method: 'GET', pathAndQuery: readPathResolved })
    const probeView = stateViewOf(probeRead ? jsonRecord(probeRead.body) : null, stateField, req.stateRecordId)
    if (probeView && scalarMatches(probeView.value, expectedValue)) { mutationEncoding = encoding; break }
  }
  const probeView = stateViewOf(probeRead ? jsonRecord(probeRead.body) : null, stateField, req.stateRecordId)
  const mutated = Boolean(probeView && probeRead && probeRead.status >= 200 && probeRead.status < 300 &&
    !scalarMatches(probeView.value, baselineValue))
  if (mutated && probeView) expectedValue = probeView.value as string | number | boolean

  // Restore the baseline with a same-origin token-bound control. If the control cannot mutate the
  // same field, the "probe succeeded" evidence is not trustworthy (the route may ignore writes).
  const controlEncoded = encodeBody(controlValue, mutationEncoding ?? 'json')
  const controlWrite = await send({
    method,
    pathAndQuery: req.pathAndQuery,
    headers: { ...controlEncoded.headers, Origin: req.origin, Referer: `${req.origin}/` },
    body: controlEncoded.body,
    csrfBind: true,
  })
  const controlRead = controlWrite && controlWrite.status >= 200 && controlWrite.status < 300
    ? await send({ method: 'GET', pathAndQuery: readPathResolved })
    : null
  const controlView = stateViewOf(controlRead ? jsonRecord(controlRead.body) : null, stateField, req.stateRecordId)
  const controlRestored = Boolean(controlView && (
    scalarMatches(controlView.value, controlValue) ||
    (mutated && scalarMatches(controlView.value, expectedValue))
  ))

  const details = {
    stateField, baselineValue, controlValue, expectedValue, bodyField,
    baselineStatus: baseline.status, probeStatus: probeWrite?.status ?? null,
    probeReadStatus: probeRead?.status ?? null,
    controlStatus: controlWrite?.status ?? null,
    controlRestored,
    mutated,
    encoding: mutationEncoding,
  }
  if (!mutated || !controlRestored) {
    return {
      verdict: 'no_signal',
      summary: mutated
        ? 'The tokenless write mutated state but the token-bound control could not restore it; treating the differential as unstable.'
        : 'The tokenless cross-origin write did not change the documented state (or was rejected).',
      details,
    }
  }
  anomalies.push({
    type: 'csrf_state_change',
    path: req.pathAndQuery,
    method,
    bodyField,
    readPath: readPathResolved,
    stateField,
    controlValue,
    expectedValue,
    ...(mutationEncoding ? { bodyEncoding: mutationEncoding } : {}),
    ...(req.stateRecordId ? { stateRecordId: req.stateRecordId } : {}),
  })
  return {
    verdict: 'signal',
    summary: 'A cookie-authenticated state change succeeded without the anti-CSRF token and the documented read route proved the mutation.',
    details,
  }
}

export const csrfProbe: ProbeModule = {
  family: 'csrf',
  classes: ['csrf_state_change'],
  run: (ctx) => diffCsrfStateChange(ctx),
}
