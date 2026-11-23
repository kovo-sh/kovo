// Realism Fixture #1 — Modern enterprise SPA.
// Split hosts (assets / app / api / external IdP), OIDC redirect login, hybrid
// HttpOnly cookie + Bearer + X-Tenant-Id, GraphQL without introspection, interactive
// tab/modal routes, and a stored XSS that renders only in the authenticated admin view.
import { randomBytes } from 'node:crypto'
import {
  Router,
  allowCors,
  bearer,
  headerValue,
  jsonBody,
  parseCookies,
  redirect,
  sendHtml,
  sendJson,
  serve,
  serializeCookie,
  type Ctx,
} from '../../lib/http.ts'
import { assertLocalLabAllowed } from '../../lib/safety.ts'
import { MemStore } from '../../lib/store.ts'
import { escapeHtml, template } from '../../lib/dom.ts'
import { createOidcKeys, decodeJwt, signRs256, verifyRs256, type OidcKeys } from '../../lib/tokens.ts'
import type { ApiRefEntry, FixtureStartOptions, Persona, StartedFixture } from '../../lib/types.ts'

interface UserRow {
  id: string
  email: string
  password: string
  role: 'member' | 'admin'
  tenant: string
}

const CLIENT_ID = 'guardian-spa'
const CLIENT_SECRET = 'rbs_fake_oidc_client_secret_2026'
const USERS: UserRow[] = [
  { id: 'u-alpha-1', email: 'alice@alpha.example.invalid', password: 'rb_fake_alice_pw', role: 'member', tenant: 'tenant-alpha' },
  { id: 'u-beta-1', email: 'bob@beta.example.invalid', password: 'rb_fake_bob_pw', role: 'member', tenant: 'tenant-beta' },
  { id: 'u-alpha-admin', email: 'admin@alpha.example.invalid', password: 'rb_fake_admin_pw', role: 'admin', tenant: 'tenant-alpha' },
]

export interface HostOrigins extends Record<string, string> {
  assets: string
  app: string
  api: string
  idp: string
}

export interface EnterpriseSpaFixture extends StartedFixture {
  hostOrigins: HostOrigins
  /** Mint a cookie-authenticated browser session (lab helper; the IdP flow is exercised too). */
  browserCookie: (personaId: string) => string
}

function mintAccessToken(user: UserRow, keys: OidcKeys, issuer: string, ttlSeconds = 3600): string {
  return signRs256(
    {
      iss: issuer,
      aud: CLIENT_ID,
      sub: user.id,
      email: user.email,
      role: user.role,
      tenant: user.tenant,
      exp: Math.floor(Date.now() / 1000) + ttlSeconds,
    },
    keys,
  )
}

function findUserByEmail(email: string | null | undefined): UserRow | null {
  if (!email) return null
  return USERS.find((u) => u.email.toLowerCase() === email.toLowerCase()) ?? null
}

export async function start(options: FixtureStartOptions = {}): Promise<EnterpriseSpaFixture> {
  void options
  assertLocalLabAllowed()
  const keys = createOidcKeys()
  const sessions = new Map<string, { user: UserRow }>()
  const notes = new MemStore()
  let noteSeq = 0

  notes.insert('notes', {
    id: 'note-seed-alpha',
    tenant: 'tenant-alpha',
    author: 'alice@alpha.example.invalid',
    body: 'Quarterly planning notes — internal only.',
    createdAt: 1,
  })
  notes.insert('notes', {
    id: 'note-seed-beta',
    tenant: 'tenant-beta',
    author: 'bob@beta.example.invalid',
    body: 'Beta tenant canary rbs_fake_beta_note_canary.',
    createdAt: 1,
  })

  // ---------- assets.local (CDN) ----------
  const assets = new Router()
  const chunks = [
    { path: 'chunks/app.js', body: 'window.__SPA__={bootstrap:true,routeTable:["dashboard","admin"]};' },
    { path: 'chunks/routes/dashboard.js', body: 'export const route="dashboard";export const tabs=["overview","activity"];' },
    { path: 'chunks/routes/admin.js', body: 'export const route="admin";export const tabs=["members","inbox"];' },
    { path: 'chunks/vendor/graphql-client.js', body: 'export async function gql(q,v){return fetch("/api/graphql",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({query:q,variables:v})}).then(r=>r.json())}' },
    { path: 'chunks/styles.css', body: '.tab{display:inline-block}.modal{border:1px solid #333}' },
  ]
  assets.get('/manifest.json', (ctx) => {
    sendJson(ctx.res, 200, { name: 'enterprise-spa', chunks: chunks.map((c) => c.path), version: 7 })
  })
  for (const chunk of chunks) {
    assets.get(`/${chunk.path}`, (ctx) => {
      const type = chunk.path.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8'
      sendHtml(ctx.res, 200, chunk.body, { 'content-type': type, 'cache-control': 'public, max-age=60' })
    })
  }
  assets.get('/health', (ctx) => sendJson(ctx.res, 200, { ok: true, host: 'assets.local' }))
  const assetsServer = await serve(assets, { name: 'assets.local' })

  // ---------- idp.local (external OIDC IdP) ----------
  const idp = new Router()
  const authCodes = new Map<string, { user: UserRow; redirectUri: string }>()
  let idpIssuer = ''
  let apiOrigin = ''

  const discovery = () => ({
    issuer: idpIssuer,
    authorization_endpoint: `${idpIssuer}/authorize`,
    token_endpoint: `${idpIssuer}/token`,
    jwks_uri: `${idpIssuer}/jwks`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'email', 'profile'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
  })

  idp.get('/.well-known/openid-configuration', (ctx) => sendJson(ctx.res, 200, discovery()))
  idp.get('/jwks', (ctx) => sendJson(ctx.res, 200, { keys: [keys.jwk] }))
  idp.get('/authorize', (ctx) => {
    const clientId = ctx.query.get('client_id')
    const responseType = ctx.query.get('response_type')
    const redirectUri = ctx.query.get('redirect_uri')
    if (clientId !== CLIENT_ID || responseType !== 'code' || !redirectUri) {
      sendJson(ctx.res, 400, { error: 'invalid_request' })
      return
    }
    const loginHint = ctx.query.get('login_hint') ?? ctx.query.get('user') ?? 'alice@alpha.example.invalid'
    const user = findUserByEmail(loginHint)
    if (!user) {
      sendJson(ctx.res, 400, { error: 'unknown_user' })
      return
    }
    const code = randomBytes(12).toString('hex')
    authCodes.set(code, { user, redirectUri })
    // Deliberate realism gap: redirect_uri is not checked against a registered allowlist.
    let target: URL
    try {
      target = new URL(redirectUri)
    } catch {
      sendJson(ctx.res, 400, { error: 'invalid_redirect_uri' })
      return
    }
    target.searchParams.set('code', code)
    const state = ctx.query.get('state')
    if (state) target.searchParams.set('state', state)
    redirect(ctx.res, target.toString())
  })
  idp.post('/token', (ctx) => {
    const form = new URLSearchParams(ctx.bodyText)
    const code = form.get('code') ?? ''
    const grant = form.get('grant_type')
    const clientId = form.get('client_id')
    const clientSecret = form.get('client_secret')
    const grantRow = authCodes.get(code)
    if (grant !== 'authorization_code' || !grantRow || clientId !== CLIENT_ID || clientSecret !== CLIENT_SECRET) {
      sendJson(ctx.res, 401, { error: 'invalid_grant' })
      return
    }
    authCodes.delete(code)
    const token = mintAccessToken(grantRow.user, keys, idpIssuer)
    sendJson(ctx.res, 200, {
      access_token: token,
      id_token: token,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'openid email profile',
    })
  })
  idp.get('/health', (ctx) => sendJson(ctx.res, 200, { ok: true, host: 'idp.local' }))
  const idpServer = await serve(idp, { name: 'idp.local' })
  idpIssuer = idpServer.origin

  // ---------- app.local (SPA host + browser-rendered admin) ----------
  const app = new Router()
  const appOrigin = () => appServer.origin

  function sessionUser(ctx: Ctx): UserRow | null {
    const sid = parseCookies(ctx.headers.cookie)['sid']
    if (!sid) return null
    return sessions.get(sid)?.user ?? null
  }

  function sessionCookie(user: UserRow): string {
    const sid = randomBytes(18).toString('hex')
    sessions.set(sid, { user })
    return serializeCookie('sid', sid, { httpOnly: true, sameSite: 'lax', maxAge: 3600 })
  }

  app.get('/', (ctx) => {
    sendHtml(
      ctx.res,
      200,
      template(
        '<!doctype html><html><head><title>Alpha Console</title><link rel="stylesheet" href="{{assets}}/chunks/styles.css"></head>' +
          '<body><div id="root" data-api="{{api}}" data-assets="{{assets}}"></div>' +
          '<p id="signin"><a href="/login?user=alice@alpha.example.invalid">Sign in</a></p>' +
          '<script type="module" src="{{assets}}/chunks/app.js"></script></body></html>',
        { assets: assetsServer.origin, api: apiOrigin },
      ),
    )
  })
  app.get('/login', (ctx) => {
    const user = ctx.query.get('user') ?? 'alice@alpha.example.invalid'
    const target = new URL(`${idpIssuer}/authorize`)
    target.searchParams.set('client_id', CLIENT_ID)
    target.searchParams.set('response_type', 'code')
    target.searchParams.set('redirect_uri', `${appOrigin()}/callback`)
    target.searchParams.set('scope', 'openid email profile')
    target.searchParams.set('state', randomBytes(8).toString('hex'))
    target.searchParams.set('login_hint', user)
    redirect(ctx.res, target.toString())
  })
  app.get('/callback', (ctx) => {
    const code = ctx.query.get('code') ?? ''
    const grant = authCodes.get(code)
    if (!grant) {
      sendHtml(ctx.res, 400, '<h1>invalid authorization code</h1>')
      return
    }
    authCodes.delete(code)
    redirect(ctx.res, '/dashboard', 302, { 'set-cookie': sessionCookie(grant.user) })
  })
  app.get('/dashboard', (ctx) => {
    const user = sessionUser(ctx)
    if (!user) {
      redirect(ctx.res, '/login')
      return
    }
    const tabs = user.role === 'admin' ? ['overview', 'members', 'inbox'] : ['overview', 'inbox']
    sendHtml(
      ctx.res,
      200,
      template(
        '<!doctype html><html><body data-user="{{user}}" data-role="{{role}}"><h1>Dashboard</h1>' +
          '<nav id="tabs">{{{tabs}}}</nav><p>Signed in as {{email}}</p>' +
          '<script type="module" src="{{assets}}/chunks/routes/dashboard.js"></script></body></html>',
        {
          user: user.id,
          role: user.role,
          email: user.email,
          assets: assetsServer.origin,
          tabs: tabs
            .map((tab) => `<a class="tab" href="/admin?tab=${tab}" data-tab="${tab}">${tab}</a>`)
            .join(''),
        },
      ),
    )
  })
  app.get('/inbox', (ctx) => {
    const user = sessionUser(ctx)
    if (!user) {
      redirect(ctx.res, '/login')
      return
    }
    const rows = notes.find('notes', (n) => n.tenant === user.tenant)
    const items = rows
      .map((n) => `<li class="note" data-note-id="${escapeHtml(n.id)}">${escapeHtml(n.body)}</li>`)
      .join('')
    sendHtml(
      ctx.res,
      200,
      `<!doctype html><html><body data-view="member-inbox"><h1>Inbox</h1><ul id="notes">${items}</ul></body></html>`,
    )
  })
  app.get('/admin', (ctx) => {
    const user = sessionUser(ctx)
    if (!user || user.role !== 'admin') {
      sendJson(ctx.res, 403, { error: 'admin_required' })
      return
    }
    const tab = ctx.query.get('tab') ?? 'overview'
    if (tab === 'members') {
      const rows = USERS.map(
        (u) =>
          `<tr class="member" data-tenant="${u.tenant}"><td>${u.id}</td><td>${escapeHtml(u.email)}</td>` +
          `<td><a data-modal="member" href="/admin/modal/member/${u.id}">open</a></td></tr>`,
      ).join('')
      sendHtml(
        ctx.res,
        200,
        '<!doctype html><html><body data-view="admin-members"><h1>Members</h1>' +
          '<nav><a class="tab" href="/admin?tab=inbox">inbox</a><a class="tab" href="/admin?tab=members">members</a></nav>' +
          `<table id="members">${rows}</table></body></html>`,
      )
      return
    }
    if (tab === 'inbox') {
      const rows = notes.all('notes')
      // Intentional: admin moderation renders stored note bodies as rich HTML.
      const items = rows
        .map(
          (n) =>
            `<li class="note" data-note-id="${escapeHtml(n.id)}" data-tenant="${escapeHtml(n.tenant)}">${String(n.body)}</li>`,
        )
        .join('')
      sendHtml(
        ctx.res,
        200,
        '<!doctype html><html><body data-view="admin-inbox"><h1>Moderation inbox</h1>' +
          '<nav><a class="tab" href="/admin?tab=members">members</a><a class="tab" href="/admin?tab=inbox">inbox</a></nav>' +
          `<ul id="admin-notes">${items}</ul></body></html>`,
      )
      return
    }
    sendHtml(
      ctx.res,
      200,
      '<!doctype html><html><body data-view="admin-overview"><h1>Admin overview</h1>' +
        '<nav><a class="tab" href="/admin?tab=members">members</a><a class="tab" href="/admin?tab=inbox">inbox</a></nav></body></html>',
    )
  })
  app.get('/admin/modal/member/:id', (ctx) => {
    const user = sessionUser(ctx)
    if (!user || user.role !== 'admin') {
      sendJson(ctx.res, 403, { error: 'admin_required' })
      return
    }
    const target = USERS.find((u) => u.id === ctx.params.id)
    if (!target) {
      sendJson(ctx.res, 404, { error: 'member_not_found' })
      return
    }
    sendHtml(
      ctx.res,
      200,
      `<div class="modal" role="dialog" data-member="${target.id}"><h2>${escapeHtml(target.email)}</h2>` +
        `<p>tenant=${escapeHtml(target.tenant)} role=${target.role}</p></div>`,
    )
  })
  app.get('/__realism__/session', (ctx) => {
    const personaId = ctx.query.get('persona') ?? 'alice'
    const user =
      personaId === 'admin'
        ? USERS.find((u) => u.role === 'admin')
        : findUserByEmail(`${personaId}@alpha.example.invalid`) ?? findUserByEmail(`${personaId}@beta.example.invalid`)
    if (!user) {
      sendJson(ctx.res, 404, { error: 'persona_not_found' })
      return
    }
    sendJson(ctx.res, 200, { user: user.id, role: user.role, tenant: user.tenant }, { 'set-cookie': sessionCookie(user) })
  })
  app.get('/health', (ctx) => sendJson(ctx.res, 200, { ok: true, host: 'app.local' }))
  const appServer = await serve(app, { name: 'app.local' })

  // ---------- api.local ----------
  const api = new Router()

  function apiUser(ctx: Ctx): { user: UserRow; mode: 'bearer' | 'cookie' } | null {
    const token = bearer(ctx)
    if (token) {
      const payload = verifyRs256(token, keys)
      if (!payload) return null
      const base = USERS.find((u) => u.id === payload.sub)
      if (!base) return null
      // Stateless APIs trust signed claims; the forged-token finding is about the missing signature check.
      return {
        user: {
          ...base,
          email: typeof payload.email === 'string' ? payload.email : base.email,
          role: payload.role === 'admin' ? 'admin' : 'member',
          tenant: typeof payload.tenant === 'string' ? payload.tenant : base.tenant,
        },
        mode: 'bearer',
      }
    }
    const session = sessions.get(parseCookies(ctx.headers.cookie)['sid'] ?? '')
    return session ? { user: session.user, mode: 'cookie' } : null
  }

  api.add('OPTIONS', '*', (ctx) => {
    ctx.res.statusCode = 204
    ctx.res.end()
  })

  api.get('/api/me', (ctx) => {
    const auth = apiUser(ctx)
    if (!auth) {
      sendJson(ctx.res, 401, { error: 'unauthorized' })
      return
    }
    sendJson(ctx.res, 200, {
      id: auth.user.id,
      email: auth.user.email,
      role: auth.user.role,
      tenant: auth.user.tenant,
      authMode: auth.mode,
    })
  })

  api.get('/api/profile', (ctx) => {
    const auth = apiUser(ctx)
    if (!auth) {
      sendJson(ctx.res, 401, { error: 'unauthorized' })
      return
    }
    if (headerValue(ctx, 'x-tenant-id') !== auth.user.tenant) {
      sendJson(ctx.res, 403, { error: 'tenant_scope_violation' })
      return
    }
    sendJson(ctx.res, 200, { id: auth.user.id, email: auth.user.email, tenant: auth.user.tenant })
  })

  api.post('/api/notes', (ctx) => {
    const auth = apiUser(ctx)
    if (!auth) {
      sendJson(ctx.res, 401, { error: 'unauthorized' })
      return
    }
    const body = jsonBody<{ body?: string }>(ctx)
    if (!body?.body) {
      sendJson(ctx.res, 400, { error: 'body_required' })
      return
    }
    const row = {
      id: `note-${++noteSeq}`,
      tenant: auth.user.tenant,
      author: auth.user.email,
      body: body.body,
      createdAt: Date.now(),
    }
    notes.insert('notes', row)
    sendJson(ctx.res, 201, row)
  })

  api.get('/api/notes', (ctx) => {
    const auth = apiUser(ctx)
    if (!auth) {
      sendJson(ctx.res, 401, { error: 'unauthorized' })
      return
    }
    sendJson(ctx.res, 200, { notes: notes.find('notes', (n) => n.tenant === auth.user.tenant) })
  })

  api.post('/api/graphql', (ctx) => {
    const auth = apiUser(ctx)
    if (!auth) {
      sendJson(ctx.res, 401, { error: 'unauthorized' })
      return
    }
    const body = jsonBody<{ query?: string; variables?: Record<string, unknown> }>(ctx)
    const query = body?.query ?? ''
    if (/__schema|__type\b/.test(query)) {
      sendJson(ctx.res, 200, { errors: [{ message: 'GraphQL introspection is disabled' }] })
      return
    }
    const memberArg = /member\s*\(\s*(?:id\s*:\s*)?"?([\w-]+)"?\s*\)/.exec(query)
    if (memberArg) {
      // Deliberate realism gap: the resolver does not scope the lookup to the caller's tenant.
      const target = USERS.find((u) => u.id === memberArg[1] || u.email === memberArg[1])
      if (!target) {
        sendJson(ctx.res, 200, { errors: [{ message: 'member_not_found' }] })
        return
      }
      sendJson(ctx.res, 200, {
        data: { member: { id: target.id, email: target.email, tenant: target.tenant, role: target.role } },
      })
      return
    }
    if (/\bnotes\b/.test(query)) {
      sendJson(ctx.res, 200, {
        data: { notes: notes.find('notes', (n) => n.tenant === auth.user.tenant).map((n) => ({ id: n.id, body: n.body })) },
      })
      return
    }
    if (/\bme\b/.test(query)) {
      sendJson(ctx.res, 200, {
        data: { me: { id: auth.user.id, email: auth.user.email, role: auth.user.role, tenant: auth.user.tenant } },
      })
      return
    }
    sendJson(ctx.res, 200, { errors: [{ message: 'unsupported_query' }] })
  })

  api.get('/api/admin/export', (ctx) => {
    const auth = apiUser(ctx)
    if (!auth) {
      sendJson(ctx.res, 401, { error: 'unauthorized' })
      return
    }
    // Deliberate realism gap: authentication is required but the admin role is never checked.
    sendJson(ctx.res, 200, {
      export: 'members',
      tenant: headerValue(ctx, 'x-tenant-id') ?? auth.user.tenant,
      rows: USERS.map((u) => ({ id: u.id, email: u.email, tenant: u.tenant, role: u.role })),
      canary: 'rbs_fake_beta_export_canary',
    })
  })

  api.post('/api/session/refresh', (ctx) => {
    const token = bearer(ctx)
    if (!token) {
      sendJson(ctx.res, 401, { error: 'unauthorized' })
      return
    }
    const parts = decodeJwt(token)
    // Deliberate realism gap: signature is not verified before trusting claims.
    if (!parts) {
      sendJson(ctx.res, 400, { error: 'malformed_token' })
      return
    }
    const claims = parts.payload
    const role = claims.role === 'admin' ? 'admin' : 'member'
    const refreshed = signRs256(
      {
        iss: idpIssuer,
        aud: CLIENT_ID,
        sub: String(claims.sub ?? 'unknown'),
        email: String(claims.email ?? 'unknown@example.invalid'),
        role,
        tenant: String(claims.tenant ?? 'tenant-alpha'),
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
      keys,
    )
    sendJson(ctx.res, 200, { access_token: refreshed, role })
  })

  api.add('ANY', '*', (ctx) => sendJson(ctx.res, 404, { error: 'not_found', path: ctx.path }))
  const apiServer = await serve(api, {
    name: 'api.local',
    cors: (ctx) => allowCors(ctx, appServer.origin, ['authorization', 'content-type', 'x-tenant-id']),
  })
  apiOrigin = apiServer.origin

  const hostOrigins: HostOrigins = {
    assets: assetsServer.origin,
    app: appServer.origin,
    api: apiServer.origin,
    idp: idpServer.origin,
  }

  const personas: Persona[] = USERS.map((user) => ({
    id: user.id,
    email: user.email,
    password: user.password,
    role: user.role,
    tenant: user.tenant,
    token: mintAccessToken(user, keys, idpServer.origin),
    notes: user.role === 'admin' ? 'Browser session only — admin inbox renders stored notes.' : 'Member of a single tenant.',
  }))

  const apiRef: ApiRefEntry[] = [
    { origin: 'app', method: 'GET', path: '/login', auth: 'none', notes: '302 redirect to the external IdP' },
    { origin: 'app', method: 'GET', path: '/callback', auth: 'none', notes: 'sets HttpOnly sid cookie' },
    { origin: 'app', method: 'GET', path: '/dashboard', auth: 'user', notes: 'cookie session' },
    { origin: 'app', method: 'GET', path: '/inbox', auth: 'user', notes: 'tenant-scoped HTML' },
    { origin: 'app', method: 'GET', path: '/admin?tab=members|inbox', auth: 'admin', notes: 'interactive tabs' },
    { origin: 'app', method: 'GET', path: '/admin/modal/member/:id', auth: 'admin', notes: 'modal fragment' },
    { origin: 'api', method: 'GET', path: '/api/me', auth: 'user', notes: 'Bearer or sid cookie' },
    { origin: 'api', method: 'GET', path: '/api/profile', auth: 'tenant', notes: 'requires X-Tenant-Id' },
    { origin: 'api', method: 'GET', path: '/api/notes', auth: 'tenant' },
    { origin: 'api', method: 'POST', path: '/api/notes', auth: 'tenant', notes: 'JSON {body}' },
    { origin: 'api', method: 'POST', path: '/api/graphql', auth: 'user', notes: 'introspection disabled' },
    { origin: 'api', method: 'POST', path: '/api/session/refresh', auth: 'user', notes: 'Bearer token refresh' },
    { origin: 'idp', method: 'GET', path: '/.well-known/openid-configuration', auth: 'none' },
    { origin: 'idp', method: 'GET', path: '/authorize', auth: 'none' },
    { origin: 'idp', method: 'POST', path: '/token', auth: 'none' },
    { origin: 'assets', method: 'GET', path: '/manifest.json', auth: 'none' },
  ]

  let stopped = false
  const stop = async () => {
    if (stopped) return
    stopped = true
    sessions.clear()
    authCodes.clear()
    notes.clear()
    await Promise.all([appServer.close(), apiServer.close(), assetsServer.close(), idpServer.close()])
  }

  const browserCookie = (personaId: string): string => {
    const user =
      personaId === 'admin'
        ? USERS.find((u) => u.role === 'admin')
        : USERS.find((u) => u.id === personaId || u.email === personaId)
    if (!user) throw new Error(`unknown persona ${personaId}`)
    const sid = randomBytes(18).toString('hex')
    sessions.set(sid, { user })
    return `sid=${sid}`
  }

  return {
    name: 'enterprise-spa',
    title: 'Modern enterprise SPA (CDN + split app/api hosts + external OIDC IdP)',
    origins: hostOrigins,
    hosts: {
      'assets.local': `127.0.0.1:${assetsServer.port}`,
      'app.local': `127.0.0.1:${appServer.port}`,
      'api.local': `127.0.0.1:${apiServer.port}`,
      'idp.local': `127.0.0.1:${idpServer.port}`,
    },
    personas,
    api: apiRef,
    routes: [
      ...app.routes.map((r) => ({ method: r.method, path: r.path })),
      ...api.routes.map((r) => ({ method: r.method, path: r.path })),
      ...idp.routes.map((r) => ({ method: r.method, path: `/idp${r.path}` })),
      ...assets.routes.map((r) => ({ method: r.method, path: `/assets${r.path}` })),
    ],
    hostOrigins,
    browserCookie,
    stop,
  }
}
