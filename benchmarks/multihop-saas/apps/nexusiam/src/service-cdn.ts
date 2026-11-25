// Public CDN: static assets, profile stylesheet caching and cache diagnostics.
import type { IncomingMessage, ServerResponse } from 'node:http'
import { sendJson, sendText, header, runIdOf, match, parseUrl } from './http.ts'
import type { CacheEntry, LabState } from './shared.ts'
import { authenticate, digest, ensureDelegation } from './policy.ts'

function profileCss(slug: string, role: string): string {
  return `.profile-${slug}{--workspace-role:${role};display:grid}\n`
}

export async function handleCdn(
  req: IncomingMessage, res: ServerResponse, state: LabState,
): Promise<void> {
  const url = parseUrl(req)
  const method = req.method ?? 'GET'
  const runId = runIdOf(req, state.runId)

  if (match(url, method, '/health')) {
    sendJson(res, 200, { service: 'cdn', ok: true })
    return
  }
  if (match(url, method, '/metrics')) {
    sendJson(res, 200, { cachedProfiles: state.cache.size, assets: 12 })
    return
  }
  if (match(url, method, '/status')) {
    sendJson(res, 200, { status: 'ok', region: 'mh-lab-1', services: 5 })
    return
  }
  if (match(url, method, '/cdn-cache')) {
    sendJson(res, 200, {
      cache: 'shared', ttl: 60,
      vary: state.profile.cacheIgnoresAuth ? ['accept-encoding'] : ['accept-encoding', 'authorization', 'cookie'],
    })
    return
  }
  if (match(url, method, '/regions')) {
    sendJson(res, 200, { regions: ['us-east-1', 'eu-west-1'] })
    return
  }

  const profile = match(url, method, '/public/profile/:slug.css')
  if (profile) {
    const slug = profile[0]!
    const session = authenticate(state, req)
    const requesterTenant = session?.tenantId ?? 'org_c'
    const authorization = header(req, 'authorization')
    const delegation = session ? ensureDelegation(state, session.userId, session.tenantId) : null
    const cacheKey = state.profile.cacheIgnoresAuth ? url.pathname : `${url.pathname}|${authorization}`
    let entry: CacheEntry | undefined = state.cache.get(cacheKey)
    if (!entry) {
      entry = {
        path: url.pathname,
        delegationKey: delegation?.key ?? '',
        userId: session?.userId ?? '',
        tenantId: requesterTenant,
        runId,
      }
      state.cache.set(cacheKey, entry)
      state.emit('cdn.profile_cache_stored', {
        path: url.pathname,
        tenantId: requesterTenant,
        delegationDigest: delegation?.digest ?? '',
        runId,
      }, session?.originPersona)
    }
    const crossTenant = Boolean(session && entry.tenantId !== session.tenantId)
    state.emit('cdn.profile_cache_served', {
      path: url.pathname,
      cacheOwnerTenant: entry.tenantId,
      requesterTenant,
      crossTenant,
      delegationKeyDigest: entry.delegationKey ? digest(entry.delegationKey) : '',
      runId,
    }, session?.originPersona)
    const headers: Record<string, string> = { 'content-type': 'text/css; charset=utf-8' }
    if (entry.delegationKey) headers['x-delegation-key'] = entry.delegationKey
    if (state.profile.cacheIgnoresAuth) {
      headers['cache-control'] = 'public, max-age=60'
    } else {
      headers.vary = 'authorization, cookie'
      headers['cache-control'] = 'private, max-age=60'
    }
    sendText(res, 200, profileCss(slug, entry.tenantId === 'org_a' ? 'owner' : 'member'), headers)
    return
  }

  const asset = match(url, method, '/assets/:name')
  if (asset) {
    sendText(res, 200, `/* nexusiam asset ${asset[0]} */\n`, { 'content-type': 'text/css; charset=utf-8' })
    return
  }
  if (match(url, method, '/manifest.json')) {
    sendJson(res, 200, { name: 'Nexus IAM', start_url: '/', icons: [] })
    return
  }
  if (match(url, method, '/robots.txt')) {
    sendText(res, 200, 'User-agent: *\nAllow: /\n')
    return
  }

  sendJson(res, 404, { error: 'not found', service: 'cdn' })
}
