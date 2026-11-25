// Partner portal: public directory, support cases, and the signed partner-file gateway.
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Egress } from '../../../lib/egress.ts'
import { parseJson, readBody, runIdOf, sendJson, sendText, match, parseUrl } from './http.ts'
import type { LabState, SupportCaseRecord } from './shared.ts'
import {
  authenticate, digest, hmac, internalHeaderPresent, internalHeaderValue, randomToken, safeEqual,
} from './policy.ts'

export interface PortalDeps {
  egress: Egress
}

async function proxy(res: ServerResponse, response: Response): Promise<void> {
  const text = await response.text()
  res.writeHead(response.status, { 'content-type': response.headers.get('content-type') ?? 'application/json' })
  res.end(text)
}

export async function handlePortal(
  req: IncomingMessage, res: ServerResponse, state: LabState, deps: PortalDeps,
): Promise<void> {
  const url = parseUrl(req)
  const method = req.method ?? 'GET'
  const runId = runIdOf(req, state.runId)
  const p = state.plan.routePrefix
  const at = (path: string): string => `${p}${path}`

  if (match(url, method, '/health')) {
    sendJson(res, 200, { service: 'portal', ok: true })
    return
  }
  if (match(url, method, '/metrics')) {
    sendJson(res, 200, {
      cases: state.cases.length, exports: state.exports.length, apps: state.apps.length,
    })
    return
  }

  if (match(url, method, `${p}/directory/apps`)) {
    sendJson(res, 200, {
      apps: state.apps.map((app) => ({
        id: app.id, name: app.name, scopes: app.scopes, owner: app.ownerTenant,
      })),
    })
    return
  }

  if (method === 'POST' && match(url, method, at('/auth/login'))) {
    const raw = await readBody(req)
    const response = await deps.egress.fetch('oauth', '/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-kovo-run-id': runId },
      body: raw,
    })
    await proxy(res, response)
    return
  }

  if (match(url, method, at('/apps'))) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    sendJson(res, 200, {
      apps: state.installations
        .filter((item) => item.tenantId === session.tenantId)
        .map((item) => ({ installationId: item.id, appId: item.appId, status: item.status })),
    })
    return
  }

  if (method === 'POST' && match(url, method, at('/cases'))) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const body = parseJson<{ subject?: string }>(await readBody(req))
    const hint = state.profile.acceptCaseActorHint &&
      internalHeaderPresent(req) && internalHeaderValue(req).length > 0
    const supportCase: SupportCaseRecord = {
      id: randomToken('mh_case_', 8),
      tenantId: session.tenantId,
      subject: (body?.subject ?? 'Billing question').slice(0, 160),
      headerHint: hint,
      forwarded: false,
      runId,
    }
    state.cases.push(supportCase)
    state.emit('case.created', {
      caseId: supportCase.id,
      tenantId: supportCase.tenantId,
      headerHint: hint,
      runId,
    }, session.originPersona)
    sendJson(res, 201, { caseId: supportCase.id, subject: supportCase.subject })
    return
  }

  const forward = match(url, method, at('/cases/:id/forward'))
  if (forward) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const supportCase = state.cases.find((item) => item.id === forward[0])
    if (!supportCase) {
      sendJson(res, 404, { error: 'unknown case' })
      return
    }
    const suppliedActor = internalHeaderValue(req)
    const forwardActor = !state.profile.stripInternalHeaders &&
      internalHeaderPresent(req) && suppliedActor.length > 0
    supportCase.forwarded = true
    state.emit('case.forwarded', {
      caseId: supportCase.id,
      tenantId: supportCase.tenantId,
      internalActor: forwardActor,
      runId,
    }, session.originPersona)
    const forwarded = await deps.egress.fetch('api', `${p}/internal/cases/${encodeURIComponent(supportCase.id)}/refund-split`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-kovo-run-id': runId,
        ...(forwardActor ? { 'x-internal-actor': suppliedActor } : {}),
      },
      body: JSON.stringify({ tenantId: supportCase.tenantId, runId }),
    })
    await proxy(res, forwarded)
    return
  }

  if (match(url, method, at('/cases'))) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    sendJson(res, 200, {
      cases: state.cases
        .filter((item) => item.tenantId === session.tenantId)
        .map((item) => ({ id: item.id, subject: item.subject, forwarded: item.forwarded })),
    })
    return
  }

  const fileRoute = match(url, method, '/files/partner/:tenant/:file')
  if (fileRoute) {
    const pathTenant = fileRoute[0]!
    const fileName = fileRoute[1]!
    const exportId = url.search.get('export') ?? ''
    const signedTenant = url.search.get('tenant') ?? ''
    const signature = url.search.get('sig') ?? ''
    const exportRecord = state.exports.find((item) => item.id === exportId)
    if (!exportRecord) {
      sendJson(res, 404, { error: 'unknown export' })
      return
    }
    const expected = hmac(state.plan.secrets.signedUrlKey, exportRecord.signedPrefix)
    if (!safeEqual(expected, signature)) {
      sendJson(res, 403, { error: 'invalid signature' })
      return
    }
    const path = `partner/${pathTenant}/${fileName}`
    const allowed = state.profile.signedPrefixTrailingSlash
      ? path.startsWith(exportRecord.signedPrefix) && path.includes(`${exportRecord.signedPrefix}/`)
      : path.startsWith(exportRecord.signedPrefix)
    if (!allowed) {
      sendJson(res, 403, { error: 'path is outside the signed prefix' })
      return
    }
    const content = state.files.get(path)
    if (!content) {
      sendJson(res, 404, { error: 'file not found' })
      return
    }
    state.emit('file.downloaded', {
      tenantSlug: pathTenant,
      signedTenant,
      path,
      urlHandleDigest: digest(`${exportRecord.signedPrefix}:${signature}`),
      exportDigest: digest(exportRecord.id),
      runId,
    })
    sendText(res, 200, content)
    return
  }

  const partnerExport = match(url, method, `/files/partner/:tenant`)
  if (partnerExport) {
    sendJson(res, 404, { error: 'file required' })
    return
  }

  const benign: Record<string, unknown> = {
    '/partners': { partners: [{ id: 'mh_partner_1', name: 'Northwind Partners' }] },
    '/categories': { categories: ['billing', 'support', 'analytics', 'payments'] },
    '/reviews': { reviews: [{ id: 'mh_review_1', app: 'Ledger Sync', rating: 5 }] },
    '/support': { channels: ['chat', 'email'] },
    '/faq': { topics: ['installation', 'billing', 'webhooks'] },
    '/status': { status: 'operational' },
    '/announcements': { items: [{ id: 'mh_ann_1', title: 'Partner billing refresh' }] },
    '/assets/app.css': { assets: ['app.css', 'theme.css'] },
    '/assets/app.js': { assets: ['app.js'] },
    '/regions': { regions: ['us', 'eu'] },
    '/plans': { plans: ['starter', 'growth'] },
  }
  for (const [path, payload] of Object.entries(benign)) {
    if (match(url, method, path)) {
      sendJson(res, 200, payload)
      return
    }
  }

  sendJson(res, 404, { error: 'not found', service: 'portal' })
}
