// Federated sign-in callback. The provider assertion is signature-checked, the account email must be
// an active member of the requested organization and the assertion tenant id must match the
// organization's configured provider tenant before a session is created.
import { createHmac, timingSafeEqual } from 'node:crypto'
import type { AppContext } from '../../src/context.ts'
import { identityForUser, userByEmail } from '../../src/auth.ts'
import { asRecord, forbidden, invalid, str } from '../../src/common.ts'

interface Assertion { iss: string; tid: string; email: string; role: string; nonce: string; sig: string }

function parseAssertion(raw: string): Assertion | null {
  if (!raw) return null
  try {
    const value = JSON.parse(raw) as Record<string, unknown>
    if (!value || typeof value !== 'object') return null
    return {
      iss: str(value.iss), tid: str(value.tid), email: str(value.email),
      role: str(value.role), nonce: str(value.nonce), sig: str(value.sig),
    }
  } catch {
    return null
  }
}

function issuerOk(issuer: string, origin: string): boolean {
  if (issuer === 'idp.loopback') return true
  try { return issuer.includes(new URL(origin).host) } catch { return false }
}

function signatureOk(a: Assertion, secret: string): boolean {
  const expected = createHmac('sha256', secret).update(`${a.tid}.${a.email}.${a.role}.${a.nonce}`).digest('hex')
  if (expected.length !== a.sig.length) return false
  try { return timingSafeEqual(Buffer.from(expected), Buffer.from(a.sig)) } catch { return false }
}

function view(ctx: AppContext, user: { external_id: string; email: string; name: string; persona: string | null }, org: string): Record<string, unknown> {
  return {
    id: user.external_id, email: user.email, name: user.name, persona: user.persona, org,
    role: ctx.roleFor(user.external_id, org), permissions: ctx.permissionsFor(user.external_id, org),
    orgs: ctx.db.all<{ org_slug: string; role: string }>(
      'SELECT org_slug, role FROM memberships WHERE user_ext_id = ? ORDER BY id', [user.external_id]),
  }
}

export default function register(ctx: AppContext): void {
  ctx.route('ssoCallback', (req) => {
    const body = asRecord(req.body)
    const query = req.query
    const raw = str(body.assertion ?? (Array.isArray(query.assertion) ? query.assertion[0] : query.assertion))
    const requested = str(body.org ?? (Array.isArray(query.org) ? query.org[0] : query.org))
    const assertion = parseAssertion(raw)
    if (!assertion) return invalid(req, 'invalid_assertion')
    const org = ctx.db.get<{ slug: string; sso_tenant: string }>(
      'SELECT slug, sso_tenant FROM orgs WHERE slug = ? OR code = ?', [requested, requested])
    if (!org) return invalid(req, 'unknown_org')
    if (!issuerOk(assertion.iss, ctx.config.idpOrigin) || !signatureOk(assertion, ctx.config.idpSecret)) {
      ctx.recordAuth({ kind: 'sso_login', transport: 'sso', org: org.slug, accepted: false, detail: { reason: 'bad_signature' } })
      return req.json({ error: 'invalid_signature' }, 401)
    }
    const user = userByEmail(ctx.db, assertion.email)
    if (!user) return req.json({ error: 'unknown_subject' }, 401)
    if (assertion.tid !== org.sso_tenant) {
      ctx.recordAuth({
        kind: 'sso_login', transport: 'sso', actorExt: user.external_id, org: org.slug, accepted: false,
        detail: { assertionTid: assertion.tid, expectedTid: org.sso_tenant },
      })
      return forbidden(req)
    }
    const member = ctx.db.get<{ id: number }>('SELECT id FROM memberships WHERE user_ext_id = ? AND org_slug = ?',
      [user.external_id, org.slug])
    if (!member) return forbidden(req)
    req.session.set('identity', { ...identityForUser(user), primaryOrg: org.slug })
    ctx.recordAuth({
      kind: 'sso_login', transport: 'sso', actorExt: user.external_id, org: org.slug, accepted: true,
      detail: { assertionTid: assertion.tid, expectedTid: org.sso_tenant },
    })
    const csrf = req.issueCsrfToken()
    return req.json({ ok: true, csrfToken: csrf, user: view(ctx, user, org.slug) })
  })
}
