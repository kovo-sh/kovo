// File listing. Returns the caller tenant's files, or, when a project id is supplied, the files
// attached to that project once the project is confirmed to belong to the caller tenant.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, ownRows, fileView, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('listFiles', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const projectExt = req.query[app.field('projectId')]
    let rows = ownRows<Record<string, unknown>>(app, tenant, 'files')
    if (typeof projectExt === 'string' && projectExt) {
      const proj = app.byExternalId<Record<string, unknown>>('projects', projectExt)
      rows = proj && proj.tenant_id === tenant ? rows.filter((r) => r.project_id === projectExt) : []
    }
    return req.json({ items: rows.map(fileView) })
  })
}
