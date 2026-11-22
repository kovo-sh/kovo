// Files area: list (optionally by project), get metadata, upload. The download route is a planted
// site owned by its module. The list route's safe default scopes to projects owned by the caller.
import type { AppContext } from '../context.ts'
import { identity, tenantOf, ownRows, fileView, unauthorized, notFound } from '../common.ts'

export function registerFileRoutes(ctx: AppContext): void {
  ctx.route('listFiles', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const projectExt = req.query[ctx.field('projectId')]
    let rows = ownRows<Record<string, unknown>>(ctx, tenant, 'files')
    if (typeof projectExt === 'string') {
      // Safe default: only list files for projects the caller tenant owns.
      const proj = ctx.byExternalId<Record<string, unknown>>('projects', projectExt)
      rows = proj && proj.tenant_id === tenant ? rows.filter((r) => r.project_id === projectExt) : []
    }
    return req.json({ items: rows.map(fileView) })
  })

  ctx.route('getFile', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const row = ctx.byExternalId<Record<string, unknown>>('files', req.params[ctx.field('fileId')]!)
    if (!row || row.tenant_id !== tenant) return notFound(req)
    return req.json(fileView(row))
  })

  ctx.route('uploadFile', (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    const name = String(body[ctx.field('name')] ?? body.name ?? 'upload.txt')
    const ext = ctx.ids.encode('file', Date.now() % 100000)
    const path = `/tenants/${id.tenant}/files/${name}`
    ctx.vfs.write(path, String(body.content ?? ''))
    ctx.db.run('INSERT INTO files (external_id,tenant_id,project_id,name,vfs_path,note) VALUES (?,?,?,?,?,?)',
      [ext, id.tenant, String(body.project ?? ''), name, path, ''])
    return req.json({ id: ext, name }, 201)
  })
}
