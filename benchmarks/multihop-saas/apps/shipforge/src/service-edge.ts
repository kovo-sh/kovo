// Public edge: developer portal entry, request forwarding and static documentation assets.
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Egress } from '../../../lib/egress.ts'
import { readBody, sendJson, sendText, header, runIdOf, match, parseUrl } from './http.ts'
import type { LabState } from './shared.ts'
import { tenantBySlug } from './state.ts'

export interface EdgeDeps {
  egress: Egress
  apiOrigin: string
}

export async function handleEdge(
  req: IncomingMessage, res: ServerResponse, state: LabState, deps: EdgeDeps,
): Promise<void> {
  const url = parseUrl(req)
  const method = req.method ?? 'GET'
  const runId = runIdOf(req, state.runId)
  const p = state.plan.routePrefix

  if (match(url, method, '/health')) {
    sendJson(res, 200, { service: 'edge', ok: true })
    return
  }
  if (match(url, method, '/status')) {
    sendJson(res, 200, { status: 'ok', region: 'mh-lab-1', services: 5 })
    return
  }
  if (match(url, method, '/metrics')) {
    sendJson(res, 200, { requests: state.audit.length, projects: state.projects.length })
    return
  }

  const org = match(url, method, `${p}/directory/orgs/:slug`)
  if (org) {
    const tenantId = tenantBySlug(state, org[0]!)
    if (!tenantId) {
      sendJson(res, 404, { error: 'unknown organization' })
      return
    }
    const tenant = state.orgs[tenantId]
    state.emit('directory.org_view', { tenantId, slug: tenant.slug, runId })
    sendJson(res, 200, { slug: tenant.slug, name: tenant.name, region: 'us-east-1', plan: 'scale' })
    return
  }

  if (url.pathname.startsWith(`${p}/`)) {
    const raw = method === 'GET' || method === 'HEAD' ? '' : await readBody(req)
    const headers: Record<string, string> = { 'x-kovo-run-id': runId, 'x-edge-region': 'mh-lab-1' }
    const authorization = header(req, 'authorization')
    if (authorization) headers.authorization = authorization
    const contentType = header(req, 'content-type')
    if (contentType) headers['content-type'] = contentType
    const response = await deps.egress.fetch('api', `${url.pathname}${url.search}`, {
      method,
      headers,
      ...(raw ? { body: raw } : {}),
    })
    const text = await response.text()
    res.writeHead(response.status, {
      'content-type': response.headers.get('content-type') ?? 'application/json',
      'x-edge-cache': 'MISS',
    })
    res.end(text)
    return
  }

  const asset = match(url, method, '/assets/:name')
  if (asset) {
    sendText(res, 200, `/* shipforge docs asset ${asset[0]} */\n`, { 'content-type': 'text/css; charset=utf-8' })
    return
  }
  if (match(url, method, '/manifest.json')) {
    sendJson(res, 200, { name: 'Shipforge', start_url: '/', icons: [] })
    return
  }
  if (match(url, method, '/robots.txt')) {
    sendText(res, 200, 'User-agent: *\nAllow: /\n')
    return
  }
  if (match(url, method, '/regions')) {
    sendJson(res, 200, { regions: ['us-east-1', 'eu-west-1'], runners: ['shared', 'hosted'] })
    return
  }
  if (match(url, method, '/docs')) {
    sendJson(res, 200, {
      topics: ['pipelines', 'runners', 'artifacts', 'environments', 'webhooks', 'registries'],
      version: '2026.11',
    })
    return
  }

  sendJson(res, 404, { error: 'not found', service: 'edge' })
}
