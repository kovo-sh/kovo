// Public edge: directory lookups, request forwarding, signed export downloads and static assets.
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Egress } from '../../../lib/egress.ts'
import { readBody, sendJson, sendText, header, runIdOf, match, parseUrl } from './http.ts'
import type { LabState } from './shared.ts'
import { authenticate, digest, hmacHex, lastJsonNumber, verifyExport } from './policy.ts'
import { tenantBySlug } from './state.ts'

export interface EdgeDeps {
  egress: Egress
}

function serviceToken(state: LabState): string {
  return hmacHex(state.plan.secrets.serviceToken, 'service')
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
    sendJson(res, 200, { requests: state.audit.length, treasuryFiles: state.treasury.size })
    return
  }

  const directory = match(url, method, `${p}/directory/orgs/:slug`)
  if (directory) {
    const slug = directory[0]!
    const tenantId = tenantBySlug(state, slug)
    if (!tenantId) {
      sendJson(res, 404, { error: 'unknown organization' })
      return
    }
    const tenant = state.orgs[tenantId]
    const invite = state.profile.directoryShowsPendingEmail
      ? state.invites.find((item) => item.tenantId === tenantId && item.role === 'finance' && !item.revoked)
      : undefined
    const pendingEmail = invite?.emailRaw
    const viewer = authenticate(state, req)
    state.emit('directory.public_view', {
      slug,
      tenantId,
      pendingEmail: pendingEmail ?? '',
      pendingEmailDigest: pendingEmail ? digest(invite!.emailNormalized) : '',
      runId,
    }, viewer?.originPersona)
    sendJson(res, 200, {
      slug: tenant.slug,
      name: tenant.name,
      region: 'us-east-1',
      ...(pendingEmail ? { pendingEmail } : {}),
    })
    return
  }

  if (url.pathname.startsWith('/files/export/')) {
    const jobId = url.search.get('job') ?? ''
    const signedTenant = url.search.get('tenant') ?? ''
    const signature = url.search.get('sig') ?? ''
    const rest = url.pathname.slice('/files/export/'.length)
    const slash = rest.indexOf('/')
    const pathTenant = slash >= 0 ? rest.slice(0, slash) : rest
    const fileName = slash >= 0 ? rest.slice(slash + 1) : ''
    if (!jobId || !signedTenant || !fileName || !signature) {
      sendJson(res, 400, { error: 'malformed export link' })
      return
    }
    if (!verifyExport(state.plan.secrets.signedUrlKey, jobId, signedTenant, fileName, signature)) {
      state.emit('file.download_denied', { reason: 'bad_signature', path: url.pathname, runId })
      sendJson(res, 403, { error: 'invalid signature' })
      return
    }
    const prefix = `/files/export/${signedTenant}`
    const allowed = state.profile.strictExportPath
      ? url.pathname.startsWith(`${prefix}/`) && pathTenant === signedTenant
      : url.pathname.startsWith(prefix)
    if (!allowed) {
      state.emit('file.download_denied', { reason: 'path_scope', path: url.pathname, runId })
      sendJson(res, 403, { error: 'path outside signed prefix' })
      return
    }
    const response = await deps.egress.fetch('vault.internal', `/treasury/${encodeURIComponent(pathTenant)}`, {
      headers: { 'x-service-jwt': serviceToken(state), 'x-guardian-run-id': runId },
    })
    if (!response.ok) {
      sendJson(res, 404, { error: 'treasury not found' })
      return
    }
    const body = await response.text()
    const downloader = authenticate(state, req)
    state.emit('file.downloaded', {
      path: url.pathname,
      tenantSlug: pathTenant,
      signedTenant,
      bytes: Buffer.byteLength(body),
      signedUrlDigest: digest(`${jobId}:${signedTenant}:${fileName}`),
      urlHandleDigest: digest(`${jobId}:${signedTenant}:${fileName}`),
      runId,
    }, downloader?.originPersona)
    sendText(res, 200, body, { 'content-type': 'text/csv; charset=utf-8' })
    return
  }

  if (url.pathname.startsWith(`${p}/`) || url.pathname === p) {
    const raw = method === 'GET' || method === 'HEAD' ? '' : await readBody(req)
    const headers: Record<string, string> = {
      'x-guardian-run-id': runId,
      'x-edge-region': 'mh-lab-1',
    }
    const authorization = header(req, 'authorization')
    if (authorization) headers.authorization = authorization
    const contentType = header(req, 'content-type')
    if (contentType) headers['content-type'] = contentType
    if (raw) {
      const parsedAmount = lastJsonNumber(raw, 'amountCents')
      if (parsedAmount !== null) headers['x-lab-edge-amount'] = String(parsedAmount)
    }
    const response = await deps.egress.fetch('api', `${url.pathname}${url.search}`, {
      method,
      headers,
      ...(raw ? { body: raw } : {}),
    })
    const text = await response.text()
    const outHeaders: Record<string, string> = {
      'content-type': response.headers.get('content-type') ?? 'application/json',
      'x-edge-cache': 'MISS',
    }
    res.writeHead(response.status, outHeaders)
    res.end(text)
    return
  }

  const asset = match(url, method, '/assets/:name')
  if (asset) {
    sendText(res, 200, `/* paygrid asset ${asset[0]} */\n`, { 'content-type': 'text/css; charset=utf-8' })
    return
  }
  if (match(url, method, '/manifest.json')) {
    sendJson(res, 200, { name: 'Paygrid', start_url: '/', icons: [] })
    return
  }
  if (match(url, method, '/robots.txt')) {
    sendText(res, 200, 'User-agent: *\nAllow: /\n')
    return
  }
  if (match(url, method, '/cdn-cache')) {
    sendJson(res, 200, { cache: 'shared', ttl: 60, vary: ['accept-encoding'] })
    return
  }
  if (match(url, method, '/regions')) {
    sendJson(res, 200, { regions: ['us-east-1', 'eu-west-1'] })
    return
  }

  sendJson(res, 404, { error: 'not found', service: 'edge' })
}
