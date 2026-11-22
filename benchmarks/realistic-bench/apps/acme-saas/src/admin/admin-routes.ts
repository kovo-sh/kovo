// Admin + legacy surface (not referenced by the SPA — must be discovered). Safe defaults for the
// unmounted planted sites (admin function-level authz, audit-log secret leakage, reflected search
// XSS, export open redirect) live here.
import type { AppContext } from '../context.ts'
import { htmlEscape } from '../../../../lib/template.ts'
import { identity, tenantOf, roleOf, ownRows, invoiceView, memberView, unauthorized, forbidden, notFound } from '../common.ts'

function redactSecrets(text: string): string {
  return text.replace(/rbs_[a-z0-9]+_[0-9a-f]{12}/g, 'rbs_[redacted]')
}

export function registerAdminRoutes(ctx: AppContext): void {
  ctx.route('adminListTenants', (req) => {
    if (roleOf(ctx, req) !== 'admin' && roleOf(ctx, req) !== 'owner') return forbidden(req)
    const tenant = tenantOf(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT slug,external_id,name,plan_id FROM tenants WHERE slug = ?', [tenant])
    return req.json({ items: rows })
  })

  ctx.route('adminGetTenant', (req) => {
    if (roleOf(ctx, req) !== 'admin' && roleOf(ctx, req) !== 'owner') return forbidden(req)
    const row = ctx.byExternalId<Record<string, unknown>>('tenants', req.params[ctx.field('orgId')]!)
    if (!row || row.slug !== tenantOf(req)) return notFound(req)
    return req.json(row)
  })

  // Safe default: deleting a user requires an admin role in the caller tenant.
  ctx.route('adminDeleteUser', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    if (roleOf(ctx, req) !== 'admin' && roleOf(ctx, req) !== 'owner') return forbidden(req)
    ctx.db.run('DELETE FROM users WHERE external_id = ? AND tenant_id = ? AND role != ?',
      [req.params[ctx.field('memberId')]!, tenant, 'owner'])
    return req.json({ ok: true })
  })

  // Safe default: secret references are redacted from audit details before returning.
  ctx.route('adminAuditLog', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    if (roleOf(ctx, req) !== 'admin' && roleOf(ctx, req) !== 'owner') return forbidden(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM activity_log WHERE tenant_id = ? ORDER BY id', [tenant])
    return req.json({ items: rows.map((e) => ({ actor: e.actor, action: e.action, detail: redactSecrets(String(e.detail)) })) })
  })

  ctx.route('adminImpersonate', (req) => {
    if (roleOf(ctx, req) !== 'owner') return forbidden(req)
    return req.json({ ok: true, note: 'impersonation session not issued in lab' })
  })

  ctx.route('legacyListInvoices', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    return req.json({ items: ownRows(ctx, tenant, 'invoices').map(invoiceView) })
  })

  ctx.route('legacyGetUser', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const row = ctx.byExternalId<Record<string, unknown>>('users', req.params[ctx.field('memberId')]!)
    if (!row || row.tenant_id !== tenant) return notFound(req)
    return req.json(memberView(row))
  })

  // Safe default: the reflected term is escaped in every branch.
  ctx.route('reflectedSearch', (req) => {
    const term = String(req.query[ctx.field('q')] ?? '')
    const items = identity(req) ? ownRows(ctx, tenantOf(req)!, 'projects') : []
    const hits = items.filter((p) => String((p as { name: string }).name).toLowerCase().includes(term.toLowerCase()))
    return req.html(`<div class="results"><p>Results for ${htmlEscape(term)}</p><ul>${hits.map((h) => `<li>${htmlEscape((h as { name: string }).name)}</li>`).join('')}</ul></div>`)
  })

  // Safe default: only relative same-origin redirect targets are honored.
  ctx.route('exportRedirect', (req) => {
    const next = String(req.query[ctx.field('url')] ?? '')
    const target = next.startsWith('/') && !next.startsWith('//') ? next : `${ctx.plan.apiPrefix}/me`
    return req.redirect(target, 302)
  })
}
