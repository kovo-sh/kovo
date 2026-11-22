// File listing. Returns the caller tenant's files, or, when a project id is supplied, the files
// attached to that project.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, ownRows, fileView, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('listFiles', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const projectExt = req.query[app.field('projectId')]
    if (typeof projectExt === 'string' && projectExt) {
      const rows = app.db.all<Record<string, unknown>>(
        'SELECT * FROM files WHERE project_id = ? ORDER BY id', [projectExt])
      return req.json({ items: rows.map(fileView) })
    }
    return req.json({ items: ownRows<Record<string, unknown>>(app, tenant, 'files').map(fileView) })
  })
}
