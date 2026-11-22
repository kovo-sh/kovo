// Reports area: list/get/create, a render endpoint, a cached public view and an archive export. Safe
// defaults for the unmounted planted sites (template injection, cache poisoning, command injection)
// live here.
import type { AppContext } from '../context.ts'
import { htmlEscape } from '../../../../lib/template.ts'
import { identity, tenantOf, ownRows, unauthorized, notFound } from '../common.ts'

export function registerReportRoutes(ctx: AppContext): void {
  ctx.route('listReports', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const rows = ownRows<Record<string, unknown>>(ctx, tenant, 'reports')
    return req.json({ items: rows.map((rp) => ({ id: rp.external_id, name: rp.name })) })
  })

  ctx.route('getReport', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const row = ctx.byExternalId<Record<string, unknown>>('reports', req.params[ctx.field('reportId')]!)
    if (!row || row.tenant_id !== tenant) return notFound(req)
    return req.json({ id: row.external_id, name: row.name, body: row.body })
  })

  ctx.route('createReport', (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    const ext = ctx.ids.encode('report', Date.now() % 100000)
    ctx.db.run('INSERT INTO reports (external_id,tenant_id,name,template,body) VALUES (?,?,?,?,?)',
      [ext, id.tenant, String(body[ctx.field('name')] ?? body.name ?? 'Report'), String(body.template ?? ''), ''])
    return req.json({ id: ext }, 201)
  })

  // Safe default: the stored template body is treated as plain data, never rendered as source.
  ctx.route('renderReport', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const row = ctx.byExternalId<Record<string, unknown>>('reports', req.params[ctx.field('reportId')]!)
    if (!row || row.tenant_id !== tenant) return notFound(req)
    return req.html(`<section><h2>${htmlEscape(row.name)}</h2><pre>${htmlEscape(row.template)}</pre></section>`)
  })

  // Safe default: cache keyed per tenant so a warm entry is never served across tenants.
  ctx.route('publicReport', (req) => {
    const tenant = tenantOf(req)
    const row = ctx.byExternalId<Record<string, unknown>>('reports', req.params[ctx.field('reportId')]!)
    if (!row) return notFound(req)
    return req.json({ id: row.external_id, name: row.name })
  }, { cache: { queryKeys: [], headerKey: 'x-tenant', ttlMs: 30_000 } })

  // Safe default: the export name is a fixed argument; no shell metacharacters reach the command.
  ctx.route('exportReport', (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    const res = ctx.wiring.simulate('tar -czf {0} report.json', ['export.tgz'])
    return req.json({ ok: true, log: res.output.trim() })
  })
}
