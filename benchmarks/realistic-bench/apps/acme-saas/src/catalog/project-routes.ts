// Projects area: list/get/create/update/delete plus a rich-HTML project card renderer. Safe default
// implementations for any planted site route not currently mounted (create mass-assignment, stored
// card render) live here.
import type { AppContext } from '../context.ts'
import { htmlEscape } from '../../../../lib/template.ts'
import { identity, tenantOf, ownRows, projectView, unauthorized, notFound } from '../common.ts'

export function registerProjectRoutes(ctx: AppContext): void {
  ctx.route('listProjects', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    return req.json({ items: ownRows(ctx, tenant, 'projects').map(projectView) })
  })

  ctx.route('getProject', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const ext = req.params[ctx.field('projectId')]!
    const row = ctx.byExternalId<Record<string, unknown>>('projects', ext)
    if (!row || row.tenant_id !== tenant) return notFound(req)
    return req.json(projectView(row))
  })

  ctx.route('createProject', (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    const name = String(body[ctx.field('name')] ?? body.name ?? 'Untitled')
    const ext = ctx.ids.encode('project', Date.now() % 100000)
    ctx.db.run(
      'INSERT INTO projects (external_id,tenant_id,owner_id,name,description,visibility) VALUES (?,?,?,?,?,?)',
      [ext, id.tenant, id.userExtId, name, String(body.description ?? ''), 'private'],
    )
    return req.json({ id: ext, name }, 201)
  })

  ctx.route('updateProject', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const ext = req.params[ctx.field('projectId')]!
    const row = ctx.byExternalId<Record<string, unknown>>('projects', ext)
    if (!row || row.tenant_id !== tenant) return notFound(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    ctx.db.run('UPDATE projects SET name = ?, description = ? WHERE external_id = ? AND tenant_id = ?',
      [String(body.name ?? row.name), String(body.description ?? row.description), ext, tenant])
    return req.json({ ok: true })
  })

  ctx.route('deleteProject', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const ext = req.params[ctx.field('projectId')]!
    ctx.db.run('DELETE FROM projects WHERE external_id = ? AND tenant_id = ?', [ext, tenant])
    return req.json({ ok: true })
  })

  // Safe default: the card renderer escapes the stored description before embedding it.
  ctx.route('renderProjectCard', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const ext = req.params[ctx.field('projectId')]!
    const row = ctx.byExternalId<Record<string, unknown>>('projects', ext)
    if (!row || row.tenant_id !== tenant) return notFound(req)
    const html = `<article class="card"><h3>${htmlEscape(row.name)}</h3><div>${htmlEscape(row.description)}</div></article>`
    return req.html(html)
  })
}
