// OAuth surface: login sessions, marketplace app consent and delegated token exchange.
import type { IncomingMessage, ServerResponse } from 'node:http'
import { parseJson, readBody, runIdOf, sendJson, match, parseUrl } from './http.ts'
import type { ConsentRecord, LabState } from './shared.ts'
import {
  authenticate, canManage, digest, randomToken, roleFor, tenantFromSlug,
} from './policy.ts'

const WIDENED_SCOPES = ['billing.rebate', 'billing.settle']

function unique(values: string[]): string[] {
  return [...new Set(values)]
}

export async function handleOauth(req: IncomingMessage, res: ServerResponse, state: LabState): Promise<void> {
  const url = parseUrl(req)
  const method = req.method ?? 'GET'
  const runId = runIdOf(req, state.runId)

  if (match(url, method, '/health')) {
    sendJson(res, 200, { service: 'oauth', ok: true })
    return
  }
  if (match(url, method, '/metrics')) {
    sendJson(res, 200, {
      consents: state.consents.length,
      sessions: state.sessions.size,
      delegated: state.delegated.size,
      pats: state.pats.length,
    })
    return
  }

  if (method === 'POST' && match(url, method, '/login')) {
    const body = parseJson<{ email?: string; password?: string; tenant?: string }>(await readBody(req))
    const email = (body?.email ?? '').trim()
    const user = state.users.find((item) => item.email === email)
    if (!user || !body?.password || user.password !== body.password) {
      sendJson(res, 401, { error: 'invalid credentials' })
      return
    }
    const tenantId = body.tenant ? tenantFromSlug(state, body.tenant) : user.tenantId
    if (!tenantId) {
      sendJson(res, 404, { error: 'unknown tenant' })
      return
    }
    const role = roleFor(user, tenantId)
    if (!role) {
      sendJson(res, 403, { error: 'no membership in this tenant' })
      return
    }
    const token = randomToken('mh_fake_sess_')
    state.sessions.set(token, {
      token,
      userId: user.id,
      tenantId,
      role,
      originPersona: user.personaKey,
      runId,
      revoked: false,
      kind: 'session',
    })
    state.emit('session.created', {
      tenantId, userId: user.id, role, runId,
    }, user.personaKey)
    sendJson(res, 200, { token, tenant: tenantId, role, persona: user.personaKey })
    return
  }

  if (method === 'POST' && match(url, method, '/authorize')) {
    const session = authenticate(state, req)
    if (!session || session.kind !== 'session') {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    if (!canManage(session.role)) {
      sendJson(res, 403, { error: 'app consent requires admin or member' })
      return
    }
    const body = parseJson<{ appId?: string; scopes?: string[] }>(await readBody(req))
    const app = state.apps.find((item) => item.id === body?.appId)
    if (!app) {
      sendJson(res, 404, { error: 'unknown app' })
      return
    }
    const installed = state.installations.find((item) =>
      item.appId === app.id && item.tenantId === session.tenantId && item.status === 'installed')
    if (!installed) {
      sendJson(res, 409, { error: 'app is not installed in this workspace' })
      return
    }
    const displayed = unique(body?.scopes ?? ['billing.read'])
    const granted = state.profile.consentScopeWidening
      ? unique([...displayed, ...WIDENED_SCOPES])
      : unique(displayed.filter((scope) => app.scopes.includes(scope)))
    const widens = granted.some((scope) => !displayed.includes(scope))
    const consent: ConsentRecord = {
      id: randomToken('mh_consent_', 8),
      code: randomToken('mh_fake_code_', 8),
      appId: app.id,
      userId: session.userId,
      tenantId: session.tenantId,
      originPersona: session.originPersona,
      displayedScopes: displayed,
      grantedScopes: granted,
      used: false,
      revoked: false,
      runId,
    }
    state.consents.push(consent)
    state.emit('oauth.consent_granted', {
      consentId: consent.id,
      consentDigest: digest(consent.id),
      appId: app.id,
      tenantId: consent.tenantId,
      displayed: displayed.join(','),
      granted: granted.join(','),
      widens,
      runId,
    }, session.originPersona)
    sendJson(res, 200, {
      consentId: consent.id,
      code: consent.code,
      displayedScopes: displayed,
      grantedScopes: granted,
      widened: widens,
    })
    return
  }

  if (method === 'POST' && match(url, method, '/token')) {
    const body = parseJson<{ consentId?: string; code?: string }>(await readBody(req))
    const consent = state.consents.find((item) => item.id === body?.consentId)
    if (!consent || consent.revoked || consent.used || !body?.code || consent.code !== body.code) {
      sendJson(res, 400, { error: 'consent code is not redeemable' })
      return
    }
    consent.used = true
    const token = randomToken('mh_fake_pat_', 16)
    const widened = consent.grantedScopes.some((scope) => !consent.displayedScopes.includes(scope))
    state.delegated.set(token, {
      token,
      consentId: consent.id,
      appId: consent.appId,
      userId: consent.userId,
      tenantId: consent.tenantId,
      originPersona: consent.originPersona,
      scopes: consent.grantedScopes,
      revoked: false,
      runId,
    })
    state.emit('oauth.token_exchanged', {
      consentId: consent.id,
      consentDigest: digest(consent.id),
      tokenDigest: digest(token),
      scopes: consent.grantedScopes.join(','),
      widened,
      grant: consent.grantedScopes.includes('billing.rebate') ? 'rebate' : 'read',
      runId,
    }, consent.originPersona)
    sendJson(res, 200, {
      accessToken: token,
      scopes: consent.grantedScopes,
      widened,
      expiresIn: 3600,
    })
    return
  }

  if (method === 'POST' && match(url, method, '/revoke')) {
    const body = parseJson<{ consentId?: string }>(await readBody(req))
    const consent = state.consents.find((item) => item.id === body?.consentId)
    if (consent) consent.revoked = true
    sendJson(res, 200, { ok: true, revoked: Boolean(consent) })
    return
  }

  if (method === 'POST' && match(url, method, '/sessions/revoke')) {
    const body = parseJson<{ token?: string }>(await readBody(req))
    const token = body?.token ?? ''
    const session = state.sessions.get(token)
    if (session) session.revoked = true
    sendJson(res, 200, { ok: true, revoked: Boolean(session) })
    return
  }

  if (method === 'POST' && match(url, method, '/pats')) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const body = parseJson<{ scopes?: string[] }>(await readBody(req))
    const pat = {
      id: randomToken('mh_pat_', 6),
      token: randomToken('mh_fake_pat_', 16),
      userId: session.userId,
      tenantId: session.tenantId,
      scopes: body?.scopes ?? ['read'],
      revoked: false,
      runId,
    }
    state.pats.push(pat)
    sendJson(res, 201, { id: pat.id, token: pat.token, scopes: pat.scopes })
    return
  }

  const patRevoke = match(url, method, '/pats/:id/revoke')
  if (patRevoke) {
    const pat = state.pats.find((item) => item.id === patRevoke[0])
    if (pat) pat.revoked = true
    sendJson(res, 200, { ok: true, revoked: Boolean(pat) })
    return
  }

  if (method === 'POST' && match(url, method, '/keys/rotate')) {
    sendJson(res, 200, { rotated: true, keyId: randomToken('mh_fake_saltkey_', 6) })
    return
  }

  if (match(url, method, '/scopes')) {
    sendJson(res, 200, {
      scopes: [
        'apps.read', 'billing.read', 'billing.rebate', 'billing.settle',
        'webhooks.write', 'invoices.read', 'exports.write',
      ],
    })
    return
  }

  if (match(url, method, '/userinfo')) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    sendJson(res, 200, {
      sub: session.userId, tenant: session.tenantId, role: session.role, scopes: session.scopes,
    })
    return
  }

  if (match(url, method, '/consents')) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    sendJson(res, 200, {
      consents: state.consents
        .filter((consent) => consent.userId === session.userId)
        .map((consent) => ({
          id: consent.id, appId: consent.appId, tenant: consent.tenantId,
          displayedScopes: consent.displayedScopes, grantedScopes: consent.grantedScopes,
          used: consent.used, revoked: consent.revoked,
        })),
    })
    return
  }

  const benign: Record<string, unknown> = {
    '/clients': { clients: state.apps.map((app) => ({ id: app.id, name: app.name })) },
    '/grants': { grants: state.consents.length },
    '/jwks': { keys: [{ kid: randomToken('mh_fake_kid_', 4), alg: 'HS256' }] },
    '/discovery': { issuer: 'oauth', responseTypes: ['code'], pkce: true },
    '/introspect': { active: false },
  }
  for (const [path, payload] of Object.entries(benign)) {
    if (match(url, method, path)) {
      sendJson(res, 200, payload)
      return
    }
  }

  sendJson(res, 404, { error: 'not found', service: 'oauth' })
}
