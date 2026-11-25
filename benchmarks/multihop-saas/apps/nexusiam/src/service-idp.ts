// Identity service: sessions, OIDC-shaped endpoints, invitations and personal access tokens.
import { randomBytes } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { readBody, parseJson, sendJson, match, parseUrl, runIdOf, header } from './http.ts'
import type { InviteRecord, LabRole, LabState, PatRecord, SessionRecord, TenantKey } from './shared.ts'
import { authenticate, digest, normalizeEmail } from './policy.ts'
import { tenantBySlug } from './state.ts'

interface LoginBody {
  email?: string
  password?: string
  tenant?: string
}

function mint(prefix: string): string {
  return `${prefix}${randomBytes(9).toString('hex')}`
}

/** A delegated client is one whose share-link handoff code was delivered and linked by the app. */
function linkedDelegation(state: LabState, derivedFromDigest: string): boolean {
  if (!derivedFromDigest) return false
  for (const record of state.authCodes.values()) {
    if (record.linked && record.codeDigest === derivedFromDigest) return true
  }
  return false
}

function tenantRole(state: LabState, session: SessionRecord, tenantId: TenantKey): LabRole | null {
  return state.users.find((user) => user.id === session.userId)?.rolesByTenant[tenantId] ?? null
}

/** Invitation, token and audit administration is limited to tenant owners and admins. */
function tenantAdmin(state: LabState, session: SessionRecord, tenantId: TenantKey): boolean {
  const role = tenantRole(state, session, tenantId)
  return role === 'owner' || role === 'admin'
}

/** Registered client callbacks live on the lab loopback interface. */
function redirectRegistered(redirect: string): boolean {
  if (!redirect) return true
  try {
    const parsed = new URL(redirect)
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:')
      && (parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost')
  } catch {
    return false
  }
}

function issueSession(
  state: LabState, userIndex: number, tenantId: TenantKey, role: LabRole,
  originPersona: SessionRecord['originPersona'], runId: string,
  emailVerified: boolean, tid: TenantKey,
): SessionRecord {
  const user = state.users[userIndex]!
  const token = mint('mh_fake_sess_')
  const session: SessionRecord = {
    token, userId: user.id, tenantId, role, originPersona, runId, revoked: false, emailVerified, tid,
  }
  state.sessions.set(token, session)
  state.emit('session.issued', { tenantId, role, sessionDigest: digest(token), runId }, originPersona)
  return session
}

export async function handleIdp(
  req: IncomingMessage, res: ServerResponse, state: LabState,
): Promise<void> {
  const url = parseUrl(req)
  const method = req.method ?? 'GET'
  const runId = runIdOf(req, state.runId)

  if (match(url, method, '/health')) {
    sendJson(res, 200, { service: 'idp', ok: true })
    return
  }
  if (match(url, method, '/metrics')) {
    sendJson(res, 200, { sessions: state.sessions.size, invites: state.invites.length, pats: state.pats.length })
    return
  }

  if (method === 'POST' && match(url, method, '/login')) {
    const body = parseJson<LoginBody>(await readBody(req))
    if (!body?.email || !body.password) {
      sendJson(res, 400, { error: 'email and password required' })
      return
    }
    const index = state.users.findIndex((user) => user.email.toLowerCase() === body.email!.toLowerCase())
    const user = state.users[index]
    if (!user || user.password !== body.password || user.bot) {
      state.emit('session.login_denied', { reason: 'invalid_credentials', runId })
      sendJson(res, 401, { error: 'invalid credentials' })
      return
    }
    const requested = body.tenant ? tenantBySlug(state, body.tenant) : user.tenantId
    if (!requested) {
      sendJson(res, 400, { error: 'unknown tenant' })
      return
    }
    const role = user.rolesByTenant[requested]
    if (!role) {
      state.emit('session.login_denied', { reason: 'tenant_not_member', runId }, user.personaKey)
      sendJson(res, 403, { error: 'not a member of this tenant' })
      return
    }
    const session = issueSession(state, index, requested, role, user.personaKey, runId, user.verified, requested)
    sendJson(res, 200, {
      token: session.token,
      tenant: state.orgs[requested].slug,
      role: session.role,
      expiresIn: 3600,
    })
    return
  }

  if (match(url, method, '/logout')) {
    const session = authenticate(state, req)
    if (session) {
      session.revoked = true
      state.emit('session.revoked', { sessionDigest: digest(session.token), runId }, session.originPersona)
    }
    sendJson(res, 200, { ok: true })
    return
  }

  if (match(url, method, '/sessions/revoke')) {
    // Revocation needs a live session; an explicit token may only name one of the caller's own sessions.
    const caller = authenticate(state, req)
    if (!caller) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const body = parseJson<{ token?: string }>(await readBody(req))
    const target = body?.token ? state.sessions.get(body.token) : caller
    if (target && target.userId === caller.userId) {
      target.revoked = true
      state.emit('session.revoked', { sessionDigest: digest(target.token), runId }, target.originPersona)
    }
    sendJson(res, 200, { ok: true })
    return
  }

  const sessionParams = match(url, method, '/sessions/:id')
  if (sessionParams) {
    const caller = authenticate(state, req)
    if (!caller) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const session = state.sessions.get(sessionParams[0]!)
    if (!session || session.userId !== caller.userId) {
      sendJson(res, 404, { error: 'unknown session' })
      return
    }
    sendJson(res, 200, {
      user: session.userId, tenant: session.tenantId, role: session.role,
      revoked: session.revoked, verified: session.emailVerified,
    })
    return
  }

  if (match(url, method, '/authorize')) {
    const next = url.search.get('next') ?? ''
    const redirect = url.search.get('redirect_uri') ?? ''
    if (!redirectRegistered(redirect)) {
      state.emit('idp.authorize_denied', { reason: 'redirect_uri_not_registered', next, runId })
      sendJson(res, 400, { error: 'redirect_uri is not registered for this client' })
      return
    }
    if (!state.profile.redirectSubpathAccepted && next) {
      state.emit('idp.authorize_denied', { reason: 'redirect_not_allowlisted', next, runId })
      sendJson(res, 400, { error: 'redirect target is not allowlisted' })
      return
    }
    const code = mint('mh_fake_code_')
    const openRedirect = state.profile.redirectSubpathAccepted && next.startsWith('/s/')
    state.authCodes.set(code, { codeDigest: digest(code), shareHandoff: openRedirect, linked: false, runId })
    state.emit('idp.authorize_redirect', {
      codeDigest: digest(code),
      redirect: openRedirect ? next : redirect,
      next,
      openRedirect,
      runId,
    })
    sendJson(res, 200, {
      code,
      state: url.search.get('state') ?? '',
      redirect: openRedirect ? next : redirect,
    })
    return
  }

  if (method === 'POST' && match(url, method, '/token')) {
    const body = parseJson<{ code?: string }>(await readBody(req))
    // Codes are single-use and must have been issued by /authorize.
    const codes = state.authCodes
    if (!body?.code || !codes.has(body.code)) {
      state.emit('idp.token_denied', { reason: 'invalid_grant', runId })
      sendJson(res, 400, { error: 'invalid_grant' })
      return
    }
    codes.delete(body.code)
    const token = mint('mh_fake_oidc_')
    state.emit('idp.token_exchanged', { codeDigest: digest(body.code), runId })
    sendJson(res, 200, { access_token: token, token_type: 'Bearer', expires_in: 3600, scope: 'openid profile' })
    return
  }

  if (match(url, method, '/jwks')) {
    sendJson(res, 200, { keys: [{ kty: 'RSA', kid: 'mh_fake_key_1', use: 'sig', alg: 'RS256' }] })
    return
  }
  if (match(url, method, '/.well-known/openid-configuration')) {
    sendJson(res, 200, {
      issuer: 'http://idp.invalid',
      authorization_endpoint: '/authorize',
      token_endpoint: '/token',
      jwks_uri: '/jwks',
      response_types_supported: ['code'],
    })
    return
  }

  if (match(url, method, '/invites')) {
    if (method === 'GET') {
      const session = authenticate(state, req)
      if (!session) {
        sendJson(res, 401, { error: 'session required' })
        return
      }
      const tenantSlug = url.search.get('tenant') ?? ''
      const tenantId = tenantSlug ? tenantBySlug(state, tenantSlug) : session.tenantId
      if (!tenantId) {
        sendJson(res, 404, { error: 'unknown tenant' })
        return
      }
      const invites = state.invites.filter((invite) => invite.tenantId === tenantId)
      // Pending invitations are listed only to a linked delegated client, identified by the digest of
      // its share-link handoff code in x-derived-from.
      if (!state.profile.inviteListLeaksToken || !linkedDelegation(state, header(req, 'x-derived-from'))) {
        state.emit('invite.pending_denied', {
          tenantId,
          reason: 'live_role_check',
          derivedFromDigest: header(req, 'x-derived-from'),
          runId,
        }, session.originPersona)
        sendJson(res, 403, { error: 'invite listing requires tenant administration or a linked delegated client (x-derived-from)' })
        return
      }
      const listed = invites.map((invite) => {
        state.emit('invite.pending_listed', {
          tenantId,
          inviteId: invite.id,
          role: invite.role,
          leakedTokenDigest: digest(invite.token),
          derivedFromDigest: header(req, 'x-derived-from'),
          runId,
        }, session.originPersona)
        return {
          id: invite.id, tenant: invite.tenantId, role: invite.role,
          email: invite.emailRaw, revoked: invite.revoked, verified: invite.verified, token: invite.token,
        }
      })
      sendJson(res, 200, { invites: listed })
      return
    }
  }

  if (method === 'POST' && match(url, method, '/invites')) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const body = parseJson<{ tenant?: string; email?: string; role?: string }>(await readBody(req))
    const tenantId = body?.tenant ? tenantBySlug(state, body.tenant) : null
    if (!body?.email || !tenantId) {
      sendJson(res, 400, { error: 'tenant and email required' })
      return
    }
    const role = (body.role ?? 'member') as LabRole
    if (role !== 'admin' && role !== 'member' && role !== 'viewer') {
      sendJson(res, 400, { error: 'role must be admin, member or viewer' })
      return
    }
    // Issuing an invite is a privileged act reserved for owners and admins of the target tenant.
    if (!tenantAdmin(state, session, tenantId)) {
      state.emit('invite.create_denied', { tenantId, reason: 'insufficient_role', runId }, session.originPersona)
      sendJson(res, 403, { error: 'invite requires owner or admin' })
      return
    }
    const invite: InviteRecord = {
      id: mint('mh_inv_'),
      tenantId,
      emailRaw: body.email,
      emailNormalized: normalizeEmail(body.email),
      role,
      verified: true,
      revoked: false,
      stale: false,
      token: mint('mh_fake_invite_'),
      runId,
    }
    state.invites.push(invite)
    state.emit('invite.created', { inviteId: invite.id, tenantId, role: invite.role, runId }, session.originPersona)
    sendJson(res, 201, { id: invite.id, role: invite.role, tenant: tenantId })
    return
  }

  const revokeInvite = match(url, method, '/invites/:id/revoke')
  if (revokeInvite) {
    const actor = authenticate(state, req)
    if (!actor) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const invite = state.invites.find((item) => item.id === revokeInvite[0])
    if (!invite || !tenantAdmin(state, actor, invite.tenantId)) {
      sendJson(res, 404, { error: 'unknown invite' })
      return
    }
    invite.revoked = true
    state.emit('invite.revoked', { inviteId: invite.id, tenantId: invite.tenantId, runId }, actor.originPersona)
    sendJson(res, 200, { ok: true })
    return
  }

  if (method === 'POST' && match(url, method, '/invites/redeem')) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const body = parseJson<{ token?: string }>(await readBody(req))
    const invite = state.invites.find((item) => item.token === body?.token && !item.revoked)
    if (!invite) {
      state.emit('invite.redeem_denied', { reason: 'unknown_invite', runId })
      sendJson(res, 403, { error: 'invite not redeemable' })
      return
    }
    if (!state.profile.staleInviteRedeem || !invite.stale) {
      state.emit('invite.redeem_denied', { reason: 'invite_redemption_disabled', runId })
      sendJson(res, 403, { error: 'invite is no longer valid' })
      return
    }
    const originPersona = session.originPersona
    const userIndex = state.users.findIndex((user) => user.personaKey === originPersona)
    if (userIndex < 0) {
      sendJson(res, 403, { error: 'invite not redeemable' })
      return
    }
    const issued = issueSession(
      state, userIndex, invite.tenantId, invite.role, originPersona, runId, true, invite.tenantId,
    )
    state.emit('invite.redeemed_stale', {
      inviteId: invite.id,
      tenantId: invite.tenantId,
      role: invite.role,
      stale: invite.stale,
      tokenDigest: digest(invite.token),
      sessionDigest: digest(issued.token),
      runId,
    }, originPersona)
    sendJson(res, 200, { token: issued.token, tenant: state.orgs[invite.tenantId].slug, role: invite.role })
    return
  }

  if (method === 'POST' && match(url, method, '/pats')) {
    const body = parseJson<{ tenant?: string; scopes?: string[] }>(await readBody(req))
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const requestedTenant = body?.tenant ? tenantBySlug(state, body.tenant) : null
    if (body?.tenant && (!requestedTenant || !tenantRole(state, session, requestedTenant))) {
      sendJson(res, 403, { error: 'not a member of this tenant' })
      return
    }
    const pat: PatRecord = {
      id: mint('mh_pat_'),
      token: mint('mh_fake_pat_'),
      userId: session.userId,
      tenantId: requestedTenant ?? session.tenantId,
      scopes: body?.scopes ?? ['read'],
      revoked: false,
      runId,
    }
    state.pats.push(pat)
    state.emit('pat.created', { patId: pat.id, tenantId: pat.tenantId, scopes: pat.scopes.join(','), runId }, session.originPersona)
    sendJson(res, 201, { id: pat.id, token: pat.token, scopes: pat.scopes })
    return
  }

  if (match(url, method, '/pats')) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    sendJson(res, 200, {
      tokens: state.pats
        .filter((pat) => pat.userId === session.userId)
        .map((pat) => ({ id: pat.id, scopes: pat.scopes, revoked: pat.revoked })),
    })
    return
  }

  const revokePat = match(url, method, '/pats/:id/revoke')
  if (revokePat) {
    // Unknown and foreign ids share one 404; only the holder or an owner/admin of its tenant may revoke.
    const actor = authenticate(state, req)
    if (!actor) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const pat = state.pats.find((item) => item.id === revokePat[0])
    if (!pat || (pat.userId !== actor.userId && !tenantAdmin(state, actor, pat.tenantId))) {
      sendJson(res, 404, { error: 'unknown token' })
      return
    }
    pat.revoked = true
    state.emit('pat.revoked', { patId: pat.id, tenantId: pat.tenantId, runId }, actor.originPersona)
    sendJson(res, 200, { ok: true })
    return
  }

  if (match(url, method, '/users')) {
    // Directory lookups are scoped to the caller's current tenant.
    const viewer = authenticate(state, req)
    if (!viewer) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    sendJson(res, 200, {
      users: state.users
        .filter((user) => user.rolesByTenant[viewer.tenantId])
        .map((user) => ({ id: user.id, tenant: viewer.tenantId, role: user.rolesByTenant[viewer.tenantId] })),
    })
    return
  }
  if (match(url, method, '/scopes')) {
    sendJson(res, 200, { scopes: ['openid', 'profile', 'email', 'offline_access', 'docs.read', 'scim.write'] })
    return
  }
  if (match(url, method, '/keys')) {
    sendJson(res, 200, { keys: [{ kid: 'mh_fake_key_1', algorithm: 'RS256', rotatedAt: 0 }] })
    return
  }
  if (match(url, method, '/audit')) {
    const viewer = authenticate(state, req)
    if (!viewer) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    if (!tenantAdmin(state, viewer, viewer.tenantId)) {
      sendJson(res, 403, { error: 'audit log requires owner or admin' })
      return
    }
    sendJson(res, 200, {
      events: state.audit
        .filter((event) => event.detail.tenantId === viewer.tenantId)
        .slice(-50)
        .map((event) => ({ kind: event.kind, ts: event.ts })),
    })
    return
  }
  if (match(url, method, '/tenants')) {
    sendJson(res, 200, { tenants: state.distro.map((tenant) => ({ id: tenant.id, slug: tenant.slug, name: tenant.name })) })
    return
  }

  sendJson(res, 404, { error: 'not found', service: 'idp' })
}
