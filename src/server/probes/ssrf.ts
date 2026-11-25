// Probe family module — implementation moved verbatim from surface-engine.ts (no behavior change).
import type { Grant } from '.././broker.ts'
import type { CanaryBroker } from '.././canary-broker.ts'
import { injectParam, isPrivateOrLoopbackHost, responseSimilarity } from './context.ts'
import type { DiffContext, DiffOutcome, InjectedRequest } from './context.ts'
import type { ProbeModule } from './registry.ts'

/**
 * Carry the canary token as the broker's correlation id. In a local lab the broker adds it to the
 * outbound request as `X-Kovo-Trace-Id`, so the recorded exchange itself names the canary that
 * was injected. That is what lets a callback arriving after the probe window be attributed to this
 * exact request by the run-level OOB drain (the persisted request body is not indexed for search).
 */
function withCanaryCorrelation(req: InjectedRequest, token: string): InjectedRequest {
  return { ...req, traceId: token } as InjectedRequest & { traceId: string }
}



export async function diffCanaryCallback(ctx: DiffContext, canaryBroker: CanaryBroker | undefined, grant: Grant, signal: AbortSignal): Promise<DiffOutcome> {
  const { req, send, anomalies, notes } = ctx
  if (!canaryBroker) return { verdict: 'inconclusive', summary: 'CanaryBroker is unavailable; callback probing needs a Kovo Hunter-operated listener.', details: {} }
  const params = (req.ssrfParams?.length ? req.ssrfParams : req.param ? [req.param] : []).filter(p => /^[A-Za-z0-9_.\-[\]]{1,64}$/.test(p)).slice(0, 10)
  if (params.length === 0) return { verdict: 'inconclusive', summary: 'ssrfParams (candidate URL parameters) are required.', details: {} }

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
        summary: 'Canary base URL is private/loopback; configure KOVO_CANARY_PUBLIC_URL to a public operator-controlled listener before callback probing a public target.',
        details: { canaryHost: host },
      }
    }
  }
  const runId = req.runId ?? 'surface-engine'
  const minted: Array<{ param: string; variant: 'http' | 'dns' | 'header'; token: string }> = []
  const mint = (label: string) => canaryBroker.mintCanary(runId, label, ctx.origin, req.storage ? { storage: req.storage, assignmentId: req.assignmentId } : undefined)

  for (const param of params) {
    const httpCanary = mint(`ssrf:${param}:http`)
    minted.push({ param, variant: 'http', token: httpCanary.token })
    await send(withCanaryCorrelation(injectParam({ ...req, param }, httpCanary.httpUrl), httpCanary.token))
    const dnsCanary = mint(`ssrf:${param}:dns`)
    minted.push({ param, variant: 'dns', token: dnsCanary.token })
    await send(withCanaryCorrelation(injectParam({ ...req, param }, `http://${dnsCanary.dnsHost}/`), dnsCanary.token))
  }
  if (req.injectHeaders) {
    const headerCanary = mint('ssrf:x-forwarded-host')
    minted.push({ param: 'X-Forwarded-Host', variant: 'header', token: headerCanary.token })
    await send(withCanaryCorrelation({ method: 'GET', pathAndQuery: req.pathAndQuery, headers: { ...(req.headers ?? {}), 'X-Forwarded-Host': headerCanary.dnsHost } }, headerCanary.token))
  }

  // In-band fallback: fetch a loopback origin published by the target's own config/discovery route.
  // The app's egress guard treats these as legitimate service destinations, so a sink that reaches
  // them proves server-side fetch without any OOB callback port.
  const inband: Array<Record<string, unknown>> = []
  const internalTargets = (req.internalTargets ?? []).filter(u => /^https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):\d{2,5}(?:\/|$)/i.test(u)).slice(0, 2)
  let inbandHit = false
  if (internalTargets.length > 0) {
    const controlUrl = 'http://kovo-control.invalid/'
    for (const param of params.slice(0, 2)) {
      const control = await send(injectParam({ ...req, param }, controlUrl))
      for (const target of internalTargets) {
        const probe = await send(injectParam({ ...req, param }, target))
        if (!probe) continue
        const sim = control ? responseSimilarity(control.body, probe.body) : 0
        const diverged = !control || probe.status !== control.status || sim < 0.95
        inband.push({ param, target, controlStatus: control?.status ?? null, probeStatus: probe.status, similarity: sim, diverged })
        if (probe.status >= 200 && probe.status < 300 && diverged) {
          anomalies.push({
            type: 'ssrf_inband_differential',
            param,
            internalUrl: target,
            controlUrl,
            controlStatus: control?.status ?? null,
            acceptedStatus: probe.status,
            similarity: sim,
          })
          inbandHit = true
          break
        }
      }
      if (inbandHit) break
    }
  }

  const deadline = Date.now() + Math.max(500, Math.min(req.waitMs ?? 2500, 8000))
  const hits = new Map<string, ReturnType<CanaryBroker['checkCanary']>>()
  while (!signal.aborted) {
    for (const m of minted) {
      const res = canaryBroker.checkCanary(m.token, req.storage ? { storage: req.storage, runId } : undefined)
      if (res.hit) hits.set(m.token, res)
    }
    if (hits.size === minted.length || Date.now() >= deadline) break
    await new Promise<void>(resolve => setTimeout(resolve, 250))
  }
  const results = minted.map(m => {
    const res = hits.get(m.token)
    const first = res?.hits[0]
    return {
      param: m.param, variant: m.variant, token: m.token, hit: Boolean(res),
      protocol: first?.protocol ?? null, queryType: first?.queryType ?? null, remoteIp: first?.remoteIp ?? null,
    }
  })
  for (const r of results.filter(x => x.hit)) {
    anomalies.push({ type: 'canary_callback', param: r.param, variant: r.variant, protocol: r.protocol, token: r.token, remoteIp: r.remoteIp })
  }
  if (!info.dnsRunning) notes.push('DNS callback listener is not running; only HTTP callbacks can be observed.')
  const hitCount = results.filter(r => r.hit).length
  return {
    verdict: hitCount > 0 || inbandHit ? 'signal' : 'no_signal',
    summary: hitCount > 0
      ? `${hitCount} correlated out-of-band callback(s) received from the target for Kovo Hunter-minted canary tokens.`
      : inbandHit
        ? 'The sink fetched a loopback service origin published by the target itself (response differential, no OOB callback).'
        : 'No out-of-band callback was observed within the wait window.',
    details: { results, dnsListenerActive: info.dnsRunning, inband },
  }
}

export const ssrfProbe: ProbeModule = {
  family: 'ssrf',
  classes: ['ssrf_canary'],
  run: (ctx, deps) => diffCanaryCallback(ctx, deps.canaryBroker, deps.grant, deps.signal),
}
