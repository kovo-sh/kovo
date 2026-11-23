// Export download console. A finished job stays available to the teammate who queued it so support
// can reconcile billing periods without waiting for a fresh run.
import type { AppContext, ExportRow } from '../../src/context.ts'
import { notFound, param, requireSession, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('downloadExport', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const job = app.db.get<ExportRow>(
      'SELECT * FROM exports WHERE external_id = ? AND tenant_id = ?',
      [param(req, app, 'exportId'), id.tenant],
    )
    if (!job || String(job.creator_id) !== id.userExtId || job.vfs_path === '') return notFound(req)
    const content = app.vfs.read(job.vfs_path)
    if (content === null) return notFound(req)
    app.recordActivity(id.tenant, id.persona ?? id.email, 'export_downloaded', job.external_id)
    return req.json({ id: job.external_id, kind: job.kind, content })
  })
}
