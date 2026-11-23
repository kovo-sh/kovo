// Probe family module — implementation moved verbatim from surface-engine.ts (no behavior change).
import { extractCreatedIdFromJson, jsonRecord } from './context.ts'
import type { DiffContext, DiffOutcome } from './context.ts'
import type { ProbeModule } from './registry.ts'



export async function diffWorkflowInvariant(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies, notes } = ctx
  const origin = ctx.origin
  // A fresh, persona-scoped session jar starts without a CSRF token. Visit the site's token-issuing
  // read route(s) before the write so double-submit/header binding can inject it.
  if (req.session && req.csrfPrimePaths?.length) {
    for (const primePath of [...new Set(req.csrfPrimePaths)].slice(0, 3)) {
      if (!primePath.startsWith('/')) continue
      await send({ method: 'GET', pathAndQuery: primePath, persona: req.persona })
    }
  }
  const method: 'POST' | 'PUT' | 'PATCH' =
    req.method === 'PUT' || req.method === 'PATCH' ? req.method : 'POST'
  const checks: Array<Record<string, unknown>> = []
  const isOk = (ex: { status: number } | null): boolean => Boolean(ex && ex.status >= 200 && ex.status < 300)
  const asRecord = (ex: { body: string } | null): Record<string, unknown> | null => ex ? jsonRecord(ex.body) : null
  const idTemplate = (path: string): string =>
    path.replace(/:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\]/, '{{id}}')
  const recordsIn = (value: unknown): Array<Record<string, unknown>> => {
    if (Array.isArray(value)) return value.filter(v => v && typeof v === 'object' && !Array.isArray(v)) as Array<Record<string, unknown>>
    if (!value || typeof value !== 'object') return []
    const out: Array<Record<string, unknown>> = []
    for (const v of Object.values(value as Record<string, unknown>)) {
      if (Array.isArray(v)) out.push(...recordsIn(v))
      else if (v && typeof v === 'object') {
        const obj = v as Record<string, unknown>
        if (Object.values(obj).some(x => x && typeof x === 'object')) out.push(...recordsIn(obj))
        else out.push(obj)
      }
    }
    return out
  }
  const idOf = (record: Record<string, unknown>): string | null => {
    for (const key of ['id', 'ext_id', 'external_id', 'uuid']) {
      const v = record[key]
      if (typeof v === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(v)) return v
      if (typeof v === 'number' && Number.isFinite(v)) return String(v)
    }
    for (const [k, v] of Object.entries(record)) {
      if (/(?:^|_)id$/i.test(k) && (typeof v === 'string' || typeof v === 'number') &&
          /^[A-Za-z0-9_.:-]{1,128}$/.test(String(v))) return String(v)
    }
    return null
  }
  const stateOf = (record: Record<string, unknown>): string | null => {
    for (const key of ['status', 'state', 'payment_state', 'stage']) {
      const v = record[key]
      if (typeof v === 'string' && /^[a-z0-9_-]{1,32}$/i.test(v)) return v.toLowerCase()
    }
    return null
  }
  const terminalState = /^(?:approved|settled|confirmed|completed|complete|done|paid|captured|fulfilled|shipped|accepted|active|success|succeeded)$/i
  const numericLeaves = (value: unknown, prefix = '', depth = 0): Map<string, number> => {
    const out = new Map<string, number>()
    if (depth > 4 || !value || typeof value !== 'object' || Array.isArray(value)) return out
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(key)) continue
      const path = prefix ? `${prefix}.${key}` : key
      if (typeof child === 'number' && Number.isFinite(child)) out.set(path, child)
      else if (typeof child === 'string' && child.trim() !== '' && Number.isFinite(Number(child))) out.set(path, Number(child))
      else if (child && typeof child === 'object' && !Array.isArray(child)) {
        for (const [k, v] of numericLeaves(child, path, depth + 1)) out.set(k, v)
      }
    }
    return out
  }

  // Mode A: Quantity / numeric boundary invariant testing (-1, 0, overflow)
  if (req.quantityField) {
    const field = req.quantityField
    const aliases = /^(?:qty|quantity|itemQty|count)$/i.test(field)
      ? ['qty', 'quantity', 'count', 'itemQty']
      : /^(?:amount|value|total|price|cents)$/i.test(field)
        ? ['amount', 'value', 'cents', 'total']
        : [field]
    const bodyWith = (value: number): Record<string, unknown> => {
      const body = { ...(req.jsonBody ?? {}) }
      for (const name of new Set([field, ...aliases])) body[name] = value
      return body
    }
    let targetPath = req.pathAndQuery
    let readTemplate = req.workflowReadPath ? idTemplate(req.workflowReadPath) : null
    let createdId: string | null = null
    let createBody: Record<string, unknown> = {}
    if (req.createPath) {
      createBody = req.producerBody ?? {}
      const createEx = await send({
        method: 'POST', pathAndQuery: req.createPath,
        headers: { 'Content-Type': 'application/json', Origin: origin, ...(req.headers ?? {}) },
        body: JSON.stringify(createBody), persona: req.persona,
      })
      if (!isOk(createEx)) return { verdict: 'no_signal', summary: 'Quantity-invariant prerequisite create was rejected.', details: { suggestedReplayKind: 'http_chain' } }
      createdId = createEx ? extractCreatedIdFromJson(createEx.body) : null
      if (!createdId && targetPath.includes('{{id}}')) {
        return { verdict: 'no_signal', summary: 'Quantity-invariant prerequisite create returned no usable identifier.', details: { suggestedReplayKind: 'http_chain' } }
      }
      if (createdId && targetPath.includes('{{id}}')) targetPath = targetPath.replaceAll('{{id}}', encodeURIComponent(createdId))
    }
    const liveReadPath = readTemplate
      ? (createdId && readTemplate.includes('{{id}}')
        ? readTemplate.replaceAll('{{id}}', encodeURIComponent(createdId))
        : readTemplate.includes('{{id}}') ? null : readTemplate)
      : null
    const baseBody = bodyWith(1)
    const baseEx = await send({
      method,
      pathAndQuery: targetPath,
      headers: { 'Content-Type': 'application/json', Origin: origin, ...(req.headers ?? {}) },
      body: JSON.stringify(baseBody),
      persona: req.persona,
    })
    const controlRead = liveReadPath ? await send({ method: 'GET', pathAndQuery: liveReadPath, persona: req.persona }) : null
    const controlState = controlRead ? asRecord(controlRead) : null
    const testValues = [-1, -5, 0, 1_000_000]
    for (const val of testValues) {
      const ex = await send({
        method,
        pathAndQuery: targetPath,
        headers: { 'Content-Type': 'application/json', Origin: origin, ...(req.headers ?? {}) },
        body: JSON.stringify(bodyWith(val)),
        persona: req.persona,
      })
      if (!ex) continue
      const accepted = ex.status >= 200 && ex.status < 300
      checks.push({ kind: 'quantity_boundary', field, value: val, status: ex.status, accepted })
      if (!accepted) continue
      anomalies.push({
        type: 'workflow_quantity_invariant',
        field,
        value: val,
        status: ex.status,
        baselineStatus: baseEx?.status ?? null,
      })
      // Read-back conservation: the mutation is accepted and a separate readable state moved out of
      // its bound (negative subtotal, over-limit counter, …). This is the strong form.
      if (liveReadPath) {
        const probeRead = await send({ method: 'GET', pathAndQuery: liveReadPath, persona: req.persona })
        const probeState = probeRead ? asRecord(probeRead) : null
        const controlLeaves = controlState ? numericLeaves(controlState) : new Map<string, number>()
        const probeLeaves = probeState ? numericLeaves(probeState) : new Map<string, number>()
        const numericDiffs = [...probeLeaves.keys()].filter(k =>
          controlLeaves.has(k) && controlLeaves.get(k) !== probeLeaves.get(k))
        if (controlState && probeState && probeRead && probeRead.status >= 200 && probeRead.status < 300 && !anomalies.some(a => a.type === 'invariant_violation')) {
          const changed = numericDiffs.sort((a, b) =>
            Number(/subtotal|total|amount|balance|credit|stock|count|quantity|used|seats/i.test(b)) -
            Number(/subtotal|total|amount|balance|credit|stock|count|quantity|used|seats/i.test(a)))[0]
          const controlValue = changed ? controlLeaves.get(changed)! : NaN
          const probeValue = changed ? probeLeaves.get(changed)! : NaN
          const violated = changed
            ? (val < 0 ? probeValue < 0 && probeValue < controlValue : false)
            : false
          if (changed && violated) {
            anomalies.push({
              type: 'invariant_violation',
              mode: 'delta',
              field: changed.split('.').pop()!,
              stateSelector: changed,
              comparator: val < 0 ? 'lt' : 'gt',
              controlValue,
              expectedValue: probeValue,
              method,
              path: req.pathAndQuery,
              encoding: 'json',
              readPath: readTemplate,
              ...(req.csrfPrimePaths?.[0] ? { csrfPrimePath: req.csrfPrimePaths[0] } : {}),
              ...(req.createPath ? { createPath: req.createPath, createBody, createIdSelector: 'id' } : {}),
              body: bodyWith(val),
              controlBody: baseBody,
            })
            break
          }
        }
      }
      // Fallback: the mutation response itself carries a changed numeric field.
      const boundary = val <= 0 || val >= 2147483647
      const baseJson = baseEx ? jsonRecord(baseEx.body) : null
      const probeJson = jsonRecord(ex.body)
      if (boundary && baseJson && probeJson) {
        const changed = Object.keys(probeJson).find(k =>
          /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(k) &&
          (typeof probeJson[k] === 'number' || typeof baseJson[k] === 'number') &&
          Number.isFinite(Number(probeJson[k])) && Number.isFinite(Number(baseJson[k])) &&
          Number(probeJson[k]) !== Number(baseJson[k]))
        if (changed && !anomalies.some(a => a.type === 'invariant_violation')) {
          const probeChangedValue = Number(probeJson[changed])
          const violated = val < 0 ? probeChangedValue < 0 : false
          if (!violated) continue
          let activeField = field
          for (const cand of new Set([field, ...aliases])) {
            const single = await send({
              method,
              pathAndQuery: targetPath,
              headers: { 'Content-Type': 'application/json', Origin: origin, ...(req.headers ?? {}) },
              body: JSON.stringify({ ...(req.jsonBody ?? {}), [cand]: val }),
              persona: req.persona,
            })
            const singleJson = single ? jsonRecord(single.body) : null
            if (singleJson && Number(singleJson[changed]) === Number(probeJson[changed])) { activeField = cand; break }
          }
          anomalies.push({
            type: 'invariant_violation',
            mode: 'delta',
            field: changed,
            comparator: 'ne',
            controlValue: Number(baseJson[changed]),
            expectedValue: Number(probeJson[changed]),
            method,
            path: targetPath,
            encoding: 'json',
            ...(req.workflowReadPath ? { readPath: req.workflowReadPath } : {}),
            body: { ...(req.jsonBody ?? {}), [activeField]: val },
            controlBody: { ...(req.jsonBody ?? {}), [activeField]: 1 },
          })
        }
      }
    }
  }

  // Mode P: client-supplied numeric price/plan value is trusted by the server and persisted into the
  // catalog/summary that a sibling read exposes.
  if (req.priceTrust && req.workflowReadPath) {
    const readPath = req.workflowReadPath
    const before = await send({ method: 'GET', pathAndQuery: readPath, persona: req.persona })
    const beforeJson = asRecord(before)
    if (beforeJson) {
      const priceField = Object.keys(beforeJson).find(k =>
        /^(?:price|priceCents|price_cents|amount|amountCents|total|cost|cents)$/i.test(k) &&
        Number.isFinite(Number(beforeJson[k])))
      const planField = Object.keys(beforeJson).find(k =>
        /^(?:plan|planId|plan_id|tier|tierId|tier_id|subscription|subscriptionId|code)$/i.test(k) &&
        (typeof beforeJson[k] === 'string' || typeof beforeJson[k] === 'number'))
      const planValue = planField ? beforeJson[planField] : undefined
      const baseline = priceField ? Number(beforeJson[priceField]) : NaN
      if (priceField && Number.isFinite(baseline) && planValue !== undefined) {
        const target = baseline === 1 ? 2 : 1
        // Route bodies name the plan differently from the read response; send every common alias so
        // the server resolves the same current plan and only the trusted numeric field differs.
        const base = {
          plan: planValue, planId: planValue, plan_id: planValue,
          tier: planValue, tierId: planValue, tier_id: planValue,
          subscription: planValue, subscriptionId: planValue, subscription_id: planValue,
        }
        const controlBody = { ...base, [priceField]: baseline }
        const probeBody = { ...base, [priceField]: target }
        const controlEx = await send({
          method, pathAndQuery: req.pathAndQuery,
          headers: { 'Content-Type': 'application/json', Origin: origin, ...(req.headers ?? {}) },
          body: JSON.stringify(controlBody), persona: req.persona,
        })
        const controlRead = await send({ method: 'GET', pathAndQuery: readPath, persona: req.persona })
        const probeEx = await send({
          method, pathAndQuery: req.pathAndQuery,
          headers: { 'Content-Type': 'application/json', Origin: origin, ...(req.headers ?? {}) },
          body: JSON.stringify(probeBody), persona: req.persona,
        })
        const probeRead = await send({ method: 'GET', pathAndQuery: readPath, persona: req.persona })
        const controlState = asRecord(controlRead)
        const probeState = asRecord(probeRead)
        checks.push({ kind: 'price_trust', field: priceField, baseline, target, persona: req.persona ?? null, controlStatus: controlEx?.status ?? null, probeStatus: probeEx?.status ?? null, ...(controlEx && controlEx.status >= 400 ? { errorCode: (/"error"\s*:\s*"([^"]{1,60})"/.exec(controlEx.body)?.[1]) ?? '' } : {}) })
        if (isOk(controlEx) && isOk(probeEx) && controlState && probeState &&
            Number(controlState[priceField]) === baseline &&
            Number(probeState[priceField]) === target && target !== baseline) {
          anomalies.push({
            type: 'invariant_violation',
            mode: 'mismatch',
            field: priceField,
            expectedValue: target,
            controlValue: baseline,
            method,
            path: req.pathAndQuery,
            readPath,
            ...(req.csrfPrimePaths?.[0] ? { csrfPrimePath: req.csrfPrimePaths[0] } : {}),
            encoding: 'json',
            body: probeBody,
            controlBody,
          })
        }
      }
    }
  }


  // Mode R: state-transition replay. A terminal transition accepted a second time, after the object
  // already left its prerequisite state, skips the required intermediate step.
  if (req.repeatTransition) {
    let target = req.pathAndQuery
    const liveBody: Record<string, unknown> = { ...(req.jsonBody ?? {}) }
    let specBody: Record<string, unknown> = { ...liveBody }
    let targetId: string | null = null
    let seeded = false
    let beforeState: string | null = null
    let afterState: string | null = null
    let createIdSelector = 'id'
    const readPath = req.workflowReadPath ?? null
    const endpointTemplate = req.workflowTargetTemplate ?? req.pathAndQuery
    // A concrete target (resolved by the probe layer) still has a template with a placeholder; derive
    // its identifier so the replay can address the same/again-created object explicitly.
    if (!target.includes('{{id}}') && !req.createPath) {
      const templateSegs = endpointTemplate.split('?')[0].split('/').filter(Boolean)
      const liveSegs = target.split('?')[0].split('/').filter(Boolean)
      const idx = templateSegs.findIndex(seg => /^:[A-Za-z0-9_]+$|^\{[^}]+\}$|^\[[^\]]+\]$/.test(seg))
      if (idx >= 0 && liveSegs[idx] && /^[A-Za-z0-9_.:-]{1,128}$/.test(liveSegs[idx])) {
        targetId = liveSegs[idx]
        seeded = true
      }
    }
    if (target.includes('{{id}}')) {
      if (req.workflowListPath) {
        const listEx = await send({ method: 'GET', pathAndQuery: req.workflowListPath, persona: req.persona })
        if (isOk(listEx)) {
          const parsed = (() => { try { return JSON.parse(listEx!.body) } catch { return null } })()
          const records = recordsIn(parsed).filter(r => idOf(r))
          const preferred = records.find(r => {
            const s = stateOf(r)
            return Boolean(s) && !terminalState.test(s!) && !/^(?:running|cancelled|canceled|rejected|failed|deleted|closed)$/i.test(s!)
          }) ?? records[0]
          if (preferred) {
            targetId = idOf(preferred)
            beforeState = stateOf(preferred)
          }
        }
      }
      if (!targetId && req.createPath) {
        const createEx = await send({
          method: 'POST', pathAndQuery: req.createPath,
          headers: { 'Content-Type': 'application/json', Origin: origin, ...(req.headers ?? {}) },
          body: JSON.stringify(req.producerBody ?? {}), persona: req.persona,
        })
        if (isOk(createEx)) {
          targetId = createEx ? extractCreatedIdFromJson(createEx.body) : null
        }
      }
      if (targetId) {
        target = target.replaceAll('{{id}}', encodeURIComponent(targetId))
        seeded = Boolean(req.workflowListPath)
      } else {
        return { verdict: 'no_signal', summary: 'No seeded or created transition target was available.', details: { suggestedReplayKind: 'http_chain' } }
      }
    } else if (req.createPath) {
      const createEx = await send({
        method: 'POST', pathAndQuery: req.createPath,
        headers: { 'Content-Type': 'application/json', Origin: origin, ...(req.headers ?? {}) },
        body: JSON.stringify(req.producerBody ?? {}), persona: req.persona,
      })
      if (!isOk(createEx)) {
        return { verdict: 'no_signal', summary: 'Transition prerequisite create was rejected.', details: { suggestedReplayKind: 'http_chain' } }
      }
      const parsed = createEx ? asRecord(createEx) : null
      if (parsed) {
        const tokenKey = Object.keys(parsed).find(k =>
          /^(?:token|code|nonce|secret|inviteToken|invite_code|acceptToken)$/i.test(k) && typeof parsed[k] === 'string')
        if (tokenKey) {
          const token = String(parsed[tokenKey])
          for (const k of ['token', 'code', 'nonce', 'inviteToken', 'invite_code', 'acceptToken']) liveBody[k] = token
          specBody = Object.fromEntries(Object.entries(liveBody).map(([k, v]) => [k, v === token ? '{{resource_id}}' : v]))
          createIdSelector = tokenKey
        }
      }
    }
    if (readPath) {
      const liveRead = targetId && /:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\]/.test(readPath)
        ? readPath.replace(/:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\]/, encodeURIComponent(targetId))
        : readPath
      if (!liveRead.includes('{{id}}')) {
        const before = await send({ method: 'GET', pathAndQuery: liveRead, persona: req.persona })
        const beforeJson = before ? asRecord(before) : null
        if (beforeJson) beforeState = stateOf(beforeJson) ?? beforeState
      }
    }
    const first = await send({
      method, pathAndQuery: target,
      headers: { 'Content-Type': 'application/json', Origin: origin, ...(req.headers ?? {}) },
      body: JSON.stringify(liveBody),
      persona: req.persona,
    })
    if (!isOk(first)) {
      return { verdict: 'no_signal', summary: 'First transition was rejected; no consumed state to replay.', details: { status: first?.status ?? null, checks, notes: notes.slice(-6), suggestedReplayKind: 'http_chain' } }
    }
    if (readPath) {
      const liveRead = targetId && /:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\]/.test(readPath)
        ? readPath.replace(/:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\]/, encodeURIComponent(targetId))
        : readPath
      if (!liveRead.includes('{{id}}')) {
        const after = await send({ method: 'GET', pathAndQuery: liveRead, persona: req.persona })
        const afterJson = after ? asRecord(after) : null
        if (afterJson) afterState = stateOf(afterJson) ?? afterState
      }
    }
    const second = await send({
      method, pathAndQuery: target,
      headers: { 'Content-Type': 'application/json', Origin: origin, ...(req.headers ?? {}) },
      body: JSON.stringify(liveBody),
      persona: req.persona,
    })
    const stateAdvanced = !beforeState || !afterState || beforeState !== afterState
    checks.push({ kind: 'repeat_transition', status1: first?.status ?? null, status2: second?.status ?? null, beforeState, afterState })
    if (isOk(second)) {
      anomalies.push({
        type: 'workflow_step_skip',
        repeatTransition: true,
        path: target,
        targetTemplate: idTemplate(endpointTemplate),
        ...(seeded && targetId ? { targetId, seeded: true } : {}),
        ...(req.createPath ? { createPath: req.createPath, producerBody: req.producerBody ?? {}, createIdSelector } : {}),
        targetBody: specBody,
        ...(req.csrfPrimePaths?.[0] ? { csrfPrimePath: req.csrfPrimePaths[0] } : {}),
        ...(beforeState ? { fromState: beforeState } : {}),
        ...(afterState ? { toState: afterState } : {}),
        ...(readPath ? { readPath } : {}),
        status: second?.status ?? null,
      })
    }
  }

  // Mode M: aggregate cap. Repeating a money/settlement mutation must not create a second settled
  // record. The probe only accepts a body that the route parses and only signals when both calls
  // return a terminal status, so ordinary idempotent creates cannot confirm.
  if (req.repeatMutation) {
    let encode: 'json' | 'form' = 'json'
    let body: Record<string, unknown> = { ...(req.jsonBody ?? {}) }
    if (Object.keys(body).length === 0) {
      return { verdict: 'no_signal', summary: 'No numeric money field was available for the aggregate-cap probe.', details: { suggestedReplayKind: 'http_chain' } }
    }
    const firstJson = await send({
      method, pathAndQuery: req.pathAndQuery,
      headers: { 'Content-Type': 'application/json', Origin: origin, ...(req.headers ?? {}) },
      body: JSON.stringify(body), persona: req.persona,
    })
    let first = firstJson
    let firstParsed = first ? asRecord(first) : null
    let firstState = firstParsed ? stateOf(firstParsed) : null
    if (!(isOk(firstJson) && firstState && terminalState.test(firstState))) {
      encode = 'form'
      first = await send({
        method, pathAndQuery: req.pathAndQuery,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: origin, ...(req.headers ?? {}) },
        body: new URLSearchParams(Object.entries(body).map(([k, v]) => [k, String(v)])).toString(),
        persona: req.persona,
      })
      firstParsed = first ? asRecord(first) : null
      firstState = firstParsed ? stateOf(firstParsed) : null
    }
    if (!(isOk(first) && firstState && terminalState.test(firstState))) {
      return { verdict: 'no_signal', summary: 'First money mutation did not produce a settled record.', details: { status: first?.status ?? null, encoding: encode, errorCode: first ? (/("error")\s*:\s*"([^"]{1,60})"/.exec(first.body)?.[2]) ?? '' : '', checks, suggestedReplayKind: 'http_chain' } }
    }
    const second = await send({
      method, pathAndQuery: req.pathAndQuery,
      headers: encode === 'form'
        ? { 'Content-Type': 'application/x-www-form-urlencoded', Origin: origin, ...(req.headers ?? {}) }
        : { 'Content-Type': 'application/json', ...(req.headers ?? {}) },
      body: encode === 'form'
        ? new URLSearchParams(Object.entries(body).map(([k, v]) => [k, String(v)])).toString()
        : JSON.stringify(body),
      persona: req.persona,
    })
    const secondParsed = second ? asRecord(second) : null
    const secondState = secondParsed ? stateOf(secondParsed) : null
    const firstId = firstParsed ? idOf(firstParsed) : null
    const secondId = secondParsed ? idOf(secondParsed) : null
    checks.push({ kind: 'aggregate_repeat', status1: first?.status ?? null, status2: second?.status ?? null, firstState, secondState, firstId, secondId })
    if (isOk(second) && secondState && terminalState.test(secondState) &&
        (Boolean(firstId && secondId && firstId !== secondId) || !firstId || !secondId)) {
      anomalies.push({
        type: 'workflow_repeat_accepted',
        method,
        path: req.pathAndQuery,
        encoding: encode,
        body,
        statusField: 'status',
        statusValue: secondState,
        ...(req.csrfPrimePaths?.[0] ? { csrfPrimePath: req.csrfPrimePaths[0] } : {}),
        ...(firstId ? { firstId } : {}),
        ...(secondId ? { secondId } : {}),
      })
    }
  }


  // Legacy transition detector (kept for declared transitions / expected prerequisite flags).
  if (!req.repeatTransition && !req.quantityField && (req.createPath || (req.expectedTransitions && req.expectedTransitions.length >= 2))) {
    const transitions = (req.expectedTransitions ?? ['draft', 'paid', 'confirmed']).map(t => t.toLowerCase())
    let initialState = transitions[0] ?? 'draft'
    let targetPath = req.pathAndQuery
    let stateKeys: string[] = []
    let falsePrerequisites: string[] = []
    let createStatus: number | null = null
    if (req.createPath) {
      const createEx = await send({
        method: 'POST',
        pathAndQuery: req.createPath,
        headers: { 'Content-Type': 'application/json', Origin: origin, ...(req.headers ?? {}) },
        body: JSON.stringify(req.producerBody ?? req.jsonBody ?? {}),
        persona: req.ownerPersona ?? req.persona,
      })
      if (createEx) {
        createStatus = createEx.status
        const createdId = extractCreatedIdFromJson(createEx.body) ??
          (() => { const m = /["']id["']\s*:\s*(?:"([^"]{1,128})"|(\d{1,12}))/i.exec(createEx.body); return m ? (m[1] ?? m[2]) : null })()
        if (createdId && targetPath.includes('{{id}}')) {
          targetPath = targetPath.replaceAll('{{id}}', encodeURIComponent(createdId))
        }
        try {
          const parsed = JSON.parse(createEx.body) as Record<string, unknown>
          const st = parsed.status ?? parsed.state
          if (typeof st === 'string' && st.trim()) initialState = st.trim().toLowerCase()
          for (const [key, value] of Object.entries(parsed)) {
            if (typeof value === 'boolean' && /^(?:paid|payment|approved|authorized|verified|confirmed|activated|completed|fulfilled|shipped)$/i.test(key)) {
              stateKeys.push(key)
              if (value === false) falsePrerequisites.push(key)
            }
          }
        } catch { /* ignore non-JSON create bodies */ }
      } else {
        return { verdict: 'no_signal', summary: 'Prerequisite create step failed; step-skip not tested.', details: { suggestedReplayKind: 'http_chain' } }
      }
      if (createStatus !== null && (createStatus < 200 || createStatus >= 300)) {
        return { verdict: 'no_signal', summary: 'Prerequisite create step was rejected; step-skip not tested.', details: { createStatus, suggestedReplayKind: 'http_chain' } }
      }
    }

    const skipEx = await send({
      method,
      pathAndQuery: targetPath,
      headers: { 'Content-Type': 'application/json', Origin: origin, ...(req.headers ?? {}) },
      body: JSON.stringify(req.jsonBody ?? {}),
      persona: req.otherPersona ?? req.persona,
    })
    if (skipEx && skipEx.status >= 200 && skipEx.status < 300) {
      let observedState: string | null = null
      let explicitSkipped = false
      try {
        const parsed = JSON.parse(skipEx.body) as Record<string, unknown>
        const st = parsed.status ?? parsed.state
        if (typeof st === 'string' && st.trim()) observedState = st.trim().toLowerCase()
        if (parsed.skipped === true) explicitSkipped = true
      } catch { /* ignore */ }

      const initialIdx = transitions.indexOf(initialState)
      const observedIdx = observedState ? transitions.indexOf(observedState) : -1
      const stateAdvanced = observedState !== null && observedState !== initialState
      // Any fresh object (draft) whose action succeeds while its prerequisite flags are still false
      // has skipped a required step; a normal draft->paid->confirmed transition never does.
      const skippedStep = explicitSkipped ||
        (stateAdvanced && (falsePrerequisites.length > 0 || (initialIdx >= 0 && observedIdx >= initialIdx + 2)))
      checks.push({
        kind: 'step_skip',
        initialState,
        observedState,
        falsePrerequisites,
        createStatus,
        status: skipEx.status,
        skippedStep,
      })
      if (skippedStep) {
        anomalies.push({
          type: 'workflow_step_skip',
          fromState: initialState,
          toState: observedState ?? transitions[transitions.length - 1],
          falsePrerequisites,
          path: targetPath,
          targetTemplate: req.pathAndQuery,
          createPath: req.createPath ?? null,
          producerBody: req.producerBody ?? req.jsonBody ?? {},
          status: skipEx.status,
        })
      }
    }
  }

  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0
      ? 'Workflow invariant or state-transition skip anomaly observed; confirm via http_chain Replay Spec.'
      : 'No workflow invariant violations observed.',
    details: { checks, notes: notes.slice(-12), suggestedReplayKind: 'http_chain' },
  }
}

export const workflowProbe: ProbeModule = {
  family: 'workflow',
  classes: ['workflow_invariant'],
  run: (ctx) => diffWorkflowInvariant(ctx),
}
