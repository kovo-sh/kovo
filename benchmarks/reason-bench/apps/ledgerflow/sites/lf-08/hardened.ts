// Export download console. A finished job is released only while the teammate who queued it still
// holds a role that may read billing artifacts, so a changed role no longer receives them.
import type { AppContext, ExportRow } from '../../src/context.ts'
import { currentRole } from '../../src/auth.ts'
import { roleRank } from '../../src/plan.ts'
import { forbidden, notFound, param, requireSession, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('downloadExport', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const job = app.db.get<ExportRow>(
      'SELECT * FROM exports WHERE external_id = ? AND tenant_id = ?',
      [param(req, app, 'exportId'), id.tenant],
    )
    if (!job || job.vfs_path === '') return notFound(req)
    if (roleRank(currentRole(app, req)) < roleRank('member')) return forbidden(req)
    const content = app.vfs.read(job.vfs_path)
    if (content === null) return notFound(req)
    app.recordActivity(id.tenant, id.persona ?? id.email, 'export_downloaded', job.external_id)
    return req.json({ id: job.external_id, kind: job.kind, content })
  })
}
