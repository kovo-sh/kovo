// Probe family module — implementation moved verbatim from surface-engine.ts (no behavior change).
import type { BrokerExchangeResult } from '.././broker.ts'
import { randToken } from './context.ts'
import type { DiffContext, DiffOutcome, InjectedRequest } from './context.ts'
import type { ProbeModule } from './registry.ts'



/** Extract an off-origin redirect target from a 3xx Location or a client-side meta/script redirect. */
export function redirectTargetOf(ex: BrokerExchangeResult, origin: string): string | null {
  const location = ex.respHeaders.location ?? ex.respHeaders.Location
  const raw = Array.isArray(location) ? location[0] : location
  if (raw && (ex.status >= 300 && ex.status < 400)) return raw
  const meta = /<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*url\s*=\s*([^"'>\s]+)/i.exec(ex.body)
  if (meta) return meta[1]
  const js = /(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']/i.exec(ex.body)
  if (js) return js[1]
  return null
}



/** Host a browser would actually navigate to for `target`, normalising protocol-relative and `\` forms. */
export function redirectHostOf(target: string, origin: string): string | null {
  const cleaned = target.trim().replace(/\\/g, '/')
  const withScheme = cleaned.startsWith('//') ? `https:${cleaned}` : cleaned
  try {
    return new URL(withScheme, origin).hostname.toLowerCase()
  } catch { return null }
}



/** Absolute form of an observed redirect target (protocol-relative forms get an explicit scheme). */
export function absoluteRedirectTarget(target: string, origin: string): string | null {
  const cleaned = target.trim().replace(/\\/g, '/')
  const withScheme = cleaned.startsWith('//') ? `https:${cleaned}` : cleaned
  try { return new URL(withScheme, origin).toString() } catch { return null }
}



/**
 * General open-redirect differential (CWE-601). A benign same-origin control target must stay on
 * origin; an off-origin canary (absolute, protocol-relative, backslash, userinfo or trusted-prefix
 * spoof) must actually change the observed redirect host before it is reported.
 */
export async function diffOpenRedirectDifferential(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const param = req.param
  const location = req.paramLocation ?? 'query'
  if (!param) return { verdict: 'inconclusive', summary: 'open_redirect_differential needs a candidate parameter.', details: {} }
  const originHost = new URL(req.origin).hostname.toLowerCase()
  const canaryHost = `gxr${randToken(10)}.invalid`
  const controlTarget = `/kovo-return-${randToken(6)}`
  const trusted = (req.redirectBaseTargets ?? []).slice(0, 3)
  const payloads: string[] = [
    `https://${canaryHost}/cb`,
    `//${canaryHost}/cb`,
    `/\\${canaryHost}/cb`,
    `https://${originHost}.${canaryHost}/cb`,
  ]
  for (const base of trusted) {
    let host: string | null = null
    try { host = new URL(base).hostname } catch { host = null }
    if (!host || !/^[a-z0-9.-]+$/i.test(host)) continue
    payloads.push(
      `https://${host}.${canaryHost}/cb`,
      `https://${host}@${canaryHost}/cb`,
      `https://${host}\\@${canaryHost}/cb`,
    )
  }
  const requestFor = (value: string): InjectedRequest => {
    if (location === 'json') {
      return { method: req.method === 'GET' ? 'POST' : (req.method ?? 'POST'), pathAndQuery: req.pathAndQuery, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...(req.jsonBody ?? {}), [param]: value }) }
    }
    if (location === 'form') {
      return { method: req.method === 'GET' ? 'POST' : (req.method ?? 'POST'), pathAndQuery: req.pathAndQuery, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `${encodeURIComponent(param)}=${encodeURIComponent(value)}` }
    }
    const sep = req.pathAndQuery.includes('?') ? '&' : '?'
    return { method: 'GET', pathAndQuery: `${req.pathAndQuery}${sep}${encodeURIComponent(param)}=${encodeURIComponent(value)}` }
  }
  const control = await send(requestFor(controlTarget))
  if (!control) return { verdict: 'inconclusive', summary: 'Open-redirect control request failed.', details: {} }
  const controlTargetLoc = redirectTargetOf(control, req.origin)
  const controlHost = controlTargetLoc ? redirectHostOf(controlTargetLoc, req.origin) : null
  const controlStaysOnOrigin = controlHost === null || controlHost === originHost || control.status >= 400
  if (!controlStaysOnOrigin) {
    return { verdict: 'inconclusive', summary: 'The benign control already redirects off-origin; no stable baseline.', details: { controlStatus: control.status, controlHost } }
  }
  const tried: Array<Record<string, unknown>> = []
  for (const payload of payloads.slice(0, 8)) {
    if (ctx.runner.stopReason) break
    const ex = await send(requestFor(payload))
    if (!ex) continue
    const target = redirectTargetOf(ex, req.origin)
    const host = target ? redirectHostOf(target, req.origin) : null
    const offOriginCanary = Boolean(host && host !== originHost && (host === canaryHost || host.endsWith(`.${canaryHost}`)))
    const absolute = target ? absoluteRedirectTarget(target, req.origin) : null
    tried.push({ payload, status: ex.status, location: absolute?.slice(0, 200) ?? target?.slice(0, 200) ?? null, host })
    if (!offOriginCanary || !absolute) continue
    anomalies.push({
      type: 'open_redirect_differential',
      payload,
      location: absolute,
      param,
      paramLocation: location,
      method: ex.status >= 300 && ex.status < 400 ? 'GET' : (req.method ?? 'GET'),
      controlHost,
    })
    return {
      verdict: 'signal',
      summary: 'An unvalidated redirect target changed the observed redirect host to an off-origin canary.',
      details: { controlStatus: control.status, controlHost, tried },
    }
  }
  return { verdict: 'no_signal', summary: 'Redirect targets stayed on the registered origin.', details: { controlStatus: control.status, controlHost, tried } }
}

export const openRedirectProbe: ProbeModule = {
  family: 'open_redirect',
  classes: ['open_redirect_differential'],
  run: (ctx) => diffOpenRedirectDifferential(ctx),
}
