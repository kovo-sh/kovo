// Probe family module — implementation moved verbatim from surface-engine.ts (no behavior change).
import { injectUniversalParam, randToken } from './context.ts'
import type { DiffContext, DiffOutcome, SurfaceParamLocation } from './context.ts'
import type { ProbeModule } from './registry.ts'



export async function diffMassAssignment(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const baseGet = await send({
    method: 'GET',
    pathAndQuery: req.pathAndQuery,
    headers: req.headers,
    session: req.session,
    csrfBind: req.csrfBind,
  })
  if (!baseGet) return { verdict: 'inconclusive', summary: 'Baseline GET failed for mass_assignment.', details: {} }

  let baseJson: Record<string, unknown> | null = null
  try {
    const parsed = JSON.parse(baseGet.body) as unknown
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) baseJson = parsed as Record<string, unknown>
  } catch {
    baseJson = null
  }

  const baseKeys = baseJson ? Object.keys(baseJson).filter(k => /^(?:tenant_id|owner_id|team_id|org_id|account_id|role|role_id|plan|plan_id|tier|status|state|payment_state|total|amount|price|permissions|is_admin|isAdmin|admin|verified|email_verified|active|enabled|visibility|return_url|avatar_url)$/i.test(k)) : []
  const defaults = ['role', 'isAdmin', 'admin', 'is_admin', 'plan', 'tier', 'verified', 'emailVerified', 'permissions', 'orgId', 'tenantId', 'tenant_id', 'owner_id', 'team_id', 'teamField', 'orgField', 'grant', 'level', 'status', 'state', 'payment_state', 'total', 'amount', 'visibility']
  const candidates = req.candidateFields?.length ? req.candidateFields : [...new Set([...baseKeys, ...defaults])]
  const method: 'POST' | 'PUT' | 'PATCH' = req.method === 'PUT' || req.method === 'PATCH' ? req.method : 'POST'
  const location: SurfaceParamLocation = req.paramLocation === 'form' ? 'form' : 'json'
  const results: Array<Record<string, unknown>> = []
  const suppressed: string[] = []

  for (const field of candidates.slice(0, 12)) {
    const isBoolField = /^(?:is|has|verified|admin|emailVerified)/i.test(field)
    const testVal = isBoolField ? 'true' : `guardian_ma_${randToken(4)}`
    const typedVal: string | boolean = testVal === 'true' && location === 'json'
      ? true
      : testVal
    const injected = injectUniversalParam({
      pathAndQuery: req.pathAndQuery,
      param: field,
      paramLocation: location,
      value: typedVal,
      method,
      headers: req.headers,
      jsonBody: req.jsonBody,
      formBody: req.formBody,
      session: req.session,
      csrfBind: req.csrfBind,
    })
    const writeEx = await send(injected)
    if (!writeEx || writeEx.status >= 500) continue
    const followGet = await send({
      method: 'GET',
      pathAndQuery: req.pathAndQuery,
      headers: req.headers,
      session: req.session,
    })
    const persisted = (() => {
      if (!followGet) return false
      let nextJson: Record<string, unknown> | null = null
      try {
        const parsed = JSON.parse(followGet.body) as unknown
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          nextJson = parsed as Record<string, unknown>
        }
      } catch {
        nextJson = null
      }
      if (isBoolField || typedVal === true || testVal === 'true') {
        if (nextJson) {
          if (!(field in nextJson)) return false
          const nextVal = nextJson[field]
          const isNowTrue = nextVal === true || nextVal === 'true'
          if (!isNowTrue) return false
          if (baseJson && field in baseJson) {
            return nextVal !== baseJson[field]
          }
          return true
        }
        const escapedField = field.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
        const fieldTrueRe = new RegExp(`["']?${escapedField}["']?\\s*[:=]\\s*(?:"true"|'true'|true\\b)`, 'i')
        const wasTrue = baseGet ? fieldTrueRe.test(baseGet.body) : false
        return !wasTrue && fieldTrueRe.test(followGet.body)
      }
      if (nextJson && field in nextJson) {
        const changed = !baseJson || !(field in baseJson) || nextJson[field] !== baseJson[field]
        return changed && String(nextJson[field]) === String(typedVal)
      }
      return followGet.body.includes(String(typedVal))
    })()
    results.push({ field, writeStatus: writeEx.status, persisted })
    if (persisted) {
      // Classify before submitting: privilege/ownership fields are always meaningful; lifecycle
      // fields only prove mass assignment on commerce/order-shaped resources.
      const privilegeField = /(role|roles|admin|permission|privilege|grant|level|tenant|owner|team|org|plan|tier|verified|email_verified)/i
      const lifecycleField = /^(?:status|state|payment_state|total|amount|price|return_url)$/i
      const commerceRoute = /(?:order|purchase|checkout|cart|payment|refund|shipment|reversal|disbursement|credit)/i
      const emit = privilegeField.test(field) || (lifecycleField.test(field) && commerceRoute.test(req.pathAndQuery))
      if (!emit) { suppressed.push(field); continue }
      anomalies.push({ type: 'mass_assignment', field, writeStatus: writeEx.status, persisted: true })
      if (baseJson && field in baseJson) {
        const restoreVal = location === 'json' && (typeof baseJson[field] === 'boolean' || typeof baseJson[field] === 'number' || typeof baseJson[field] === 'string')
          ? (baseJson[field] as string | number | boolean)
          : String(baseJson[field])
        await send(injectUniversalParam({
          pathAndQuery: req.pathAndQuery,
          param: field,
          paramLocation: location,
          value: restoreVal,
          method,
          headers: req.headers,
          jsonBody: req.jsonBody,
          formBody: req.formBody,
          session: req.session,
          csrfBind: req.csrfBind,
        }))
      }
      break
    }
  }

  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0
      ? `Privileged field "${String(anomalies[0].field)}" persisted after ${method}; confirm via http_chain Replay Spec.`
      : 'No mass assignment persistence observed.',
    details: { results, suppressed, suggestedReplayKind: 'http_chain' },
  }
}

export const massAssignmentProbe: ProbeModule = {
  family: 'mass_assignment',
  classes: ['mass_assignment'],
  run: (ctx) => diffMassAssignment(ctx),
}
