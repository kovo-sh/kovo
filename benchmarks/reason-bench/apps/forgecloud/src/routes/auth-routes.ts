// Session + auth surface: SPA runtime config, health probe, email/password login, logout, current
// user, and a simulated multi-tenant OIDC hand-off. The callback compares the assertion tenant id
// with the requested org's configured IdP tenant before issuing a session.
import { createHmac, timingSafeEqual } from 'node:crypto'
import type { AppContext, UserRow } from '../context.ts'
import { SESSION_COOKIE, identityForUser, userByEmail, sha256 } from '../auth.ts'
import { identity, currentUser, orgOf, unauthorized, forbidden, invalid, asRecord, str } from '../common.ts'
import { hashPassword } from '../seed.ts'
import { createPrng } from '../../../../lib/prng.ts'

const UI_ROUTES = [
  'login', 'logout', 'me', 'orgs.list', 'workspaces.list', 'workspaces.current',
  'projects.list', 'projects.detail', 'projects.create', 'projects.update', 'projects.transfer',
  'pipelines.list', 'pipelines.detail', 'builds.list', 'builds.detail', 'builds.cancel',
  'streams.build', 'tokens.list', 'tokens.create', 'tokens.revoke',
  'secrets.list', 'secrets.create', 'secrets.update', 'secrets.delete', 'secrets.batch',
  'artifacts.list', 'artifacts.mint', 'exports.queue', 'exports.list',
  'deployments.list', 'deployments.create', 'deployments.detail', 'deployments.approve',
  'deployments.schedule', 'deployments.dispute', 'deployments.release', 'deployments.promote',
  'automations.list', 'automations.create', 'webhooks.list', 'webhooks.create', 'webhooks.update',
  'webhooks.deliveries', 'members.list', 'members.update', 'members.invite',
  'teams.list', 'teams.create', 'teams.addMember', 'org.permissions', 'org.settings',
  'search.facets', 'search.query', 'graphql', 'audit.list',
]

function labelFor(ctx: AppContext, key: string, fallback: string): string {
  const spec = ctx.plan.routes[key]
  if (!spec) return fallback
  const seg = spec.path.split('/').filter(Boolean).pop() ?? fallback
  return seg.replace(/[-_]/g, ' ')
}

export function registerAuthRoutes(ctx: AppContext): void {
  ctx.route('health', (req) => req.json({ status: 'ok', service: 'forgecloud' }))

  ctx.route('appConfig', (req) => {
    const api: Record<string, { method: string; path: string }> = {}
    for (const key of UI_ROUTES) {
      const r = ctx.plan.routes[key]
      if (r) api[key] = { method: r.method, path: r.path }
    }
    return req.json({
      apiPrefix: ctx.plan.apiPrefix,
      sessionCookie: SESSION_COOKIE,
      labels: ctx.labels,
      nav: {
        projects: labelFor(ctx, 'projects.list', 'pipelines'),
        builds: labelFor(ctx, 'builds.list', 'builds'),
        secrets: labelFor(ctx, 'secrets.list', 'secrets'),
        deployments: labelFor(ctx, 'deployments.list', 'deployments'),
        webhooks: labelFor(ctx, 'webhooks.list', 'webhooks'),
        members: labelFor(ctx, 'members.list', 'members'),
        search: 'search',
      },
      routes: api,
    })
  })

  ctx.route('login', (req) => {
    const body = asRecord(req.body)
    const email = str(body[ctx.field('email')] ?? body.email)
    const password = str(body.password)
    const u = userByEmail(ctx.db, email)
    if (!u || u.status !== 'active' || u.password_hash !== hashPassword(password, ctx.plan.canarySalt)) {
      return req.json({ error: 'invalid_credentials' }, 401)
    }
    req.session.set('identity', identityForUser(u))
    const csrf = req.issueCsrfToken()
    ctx.recordAuth({ kind: 'login', actorExt: u.external_id, org: u.primary_org, accepted: true })
    return req.json({ ok: true, csrfToken: csrf, user: meView(ctx, u, u.primary_org) })
  })

  ctx.route('logout', (req) => {
    req.session.destroy()
    return req.json({ ok: true })
  })

  ctx.route('me', (req) => {
    const u = currentUser(ctx, req)
    if (!u) return unauthorized(req)
    const org = orgOf(req) ?? u.primary_org
    return req.json({ user: meView(ctx, u, org), csrfToken: req.issueCsrfToken(), org })
  })

  // Simulated multi-tenant IdP: the app asks the internal provider for a signed assertion for the
  // requested email, then the callback verifies it. The provider is loopback-only.
  ctx.route('ssoStart', async (req) => {
    const q = req.query
    const email = str(Array.isArray(q.email) ? q.email[0] : q.email) ||
      str(identity(req)?.email) || str(Array.isArray(q[ctx.field('email')]) ? q[ctx.field('email')]![0] : q[ctx.field('email')])
    const qOrg = str(Array.isArray(q.org) ? q.org[0] : q.org)
    const org = qOrg ? ctx.db.get<{ slug: string; sso_tenant: string }>(
      'SELECT slug, sso_tenant FROM orgs WHERE slug = ? OR code = ?', [qOrg, qOrg]) : undefined
    if (!email || !org) return invalid(req)
    const url = `${ctx.config.idpOrigin}/assertion?email=${encodeURIComponent(email)}&tid=${encodeURIComponent(org.sso_tenant)}`
    try {
      const res = await ctx.egress.fetch(url, { method: 'GET' })
      const assertion = JSON.parse(res.body) as Record<string, unknown>
      return req.json({ assertion })
    } catch {
      return req.json({ error: 'identity_provider_unavailable' }, 502)
    }
  })

  ctx.route('ssoCallback', async (req) => {
    const body = asRecord(req.body)
    const q = req.query
    const raw = str(body.assertion ?? (Array.isArray(q.assertion) ? q.assertion[0] : q.assertion))
    const requested = str(body.org ?? (Array.isArray(q.org) ? q.org[0] : q.org))
    const assertion = decodeAssertion(raw, ctx.config.idpOrigin)
    if (!assertion) return invalid(req, 'invalid_assertion')
    const org = ctx.db.get<{ slug: string; sso_tenant: string }>(
      'SELECT slug, sso_tenant FROM orgs WHERE slug = ? OR code = ?', [requested, requested])
    if (!org) return invalid(req, 'unknown_org')
    if (!verifyAssertion(assertion, ctx)) {
      ctx.recordAuth({ kind: 'sso_login', transport: 'sso', org: org.slug, accepted: false, detail: { reason: 'bad_signature' } })
      return req.json({ error: 'invalid_signature' }, 401)
    }
    const u = userByEmail(ctx.db, assertion.email)
    if (!u) return req.json({ error: 'unknown_subject' }, 401)
    if (assertion.tid !== org.sso_tenant) {
      ctx.recordAuth({
        kind: 'sso_login', transport: 'sso', actorExt: u.external_id, org: org.slug, accepted: false,
        detail: { assertionTid: assertion.tid, expectedTid: org.sso_tenant },
      })
      return forbidden(req)
    }
    const member = ctx.db.get<{ id: number }>('SELECT id FROM memberships WHERE user_ext_id = ? AND org_slug = ?',
      [u.external_id, org.slug])
    if (!member) return forbidden(req)
    req.session.set('identity', { ...identityForUser(u), primaryOrg: org.slug })
    ctx.recordAuth({
      kind: 'sso_login', transport: 'sso', actorExt: u.external_id, org: org.slug, accepted: true,
      detail: { assertionTid: assertion.tid, expectedTid: org.sso_tenant },
    })
    const csrf = req.issueCsrfToken()
    return req.json({ ok: true, csrfToken: csrf, user: meView(ctx, u, org.slug) })
  })
}

export function meView(ctx: AppContext, u: UserRow, org: string): Record<string, unknown> {
  return {
    id: u.external_id, email: u.email, name: u.name, persona: u.persona, org,
    role: ctx.roleFor(u.external_id, org), permissions: ctx.permissionsFor(u.external_id, org),
    orgs: ctx.db.all<{ org_slug: string; role: string }>(
      'SELECT org_slug, role FROM memberships WHERE user_ext_id = ? ORDER BY id', [u.external_id]),
  }
}

interface Assertion { iss: string; tid: string; email: string; role: string; nonce: string; sig: string }

function decodeAssertion(raw: string, expectedIssuer: string): Assertion | null {
  if (!raw) return null
  let parsed: unknown
  try { parsed = JSON.parse(raw) } catch { return null }
  const a = parsed as Record<string, unknown>
  if (!a || typeof a !== 'object') return null
  return {
    iss: str(a.iss), tid: str(a.tid), email: str(a.email), role: str(a.role),
    nonce: str(a.nonce), sig: str(a.sig),
  }
}

function verifyAssertion(a: Assertion, ctx: AppContext): boolean {
  if (a.iss !== 'idp.loopback' && !a.iss.includes(expectedHost(ctx.config.idpOrigin))) return false
  const expected = createHmac('sha256', ctx.config.idpSecret)
    .update(`${a.tid}.${a.email}.${a.role}.${a.nonce}`).digest('hex')
  const got = a.sig
  if (expected.length !== got.length) return false
  try { return timingSafeEqual(Buffer.from(expected), Buffer.from(got)) } catch { return false }
}

function expectedHost(origin: string): string {
  try { return new URL(origin).host } catch { return origin }
}

/** Signed assertion helper shared with the internal IdP mock (server.ts). */
export function signAssertion(input: { tid: string; email: string; role: string; nonce: string; secret: string }): Assertion {
  const sig = createHmac('sha256', input.secret).update(`${input.tid}.${input.email}.${input.role}.${input.nonce}`).digest('hex')
  return { iss: 'idp.loopback', tid: input.tid, email: input.email, role: input.role, nonce: input.nonce, sig }
}

export function nonceFor(seed: string): string {
  return createPrng(seed).hex(8)
}

export { sha256 }
