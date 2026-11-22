// Public report view. Serves a shareable summary of a report, cached briefly so repeat hits on a
// popular link are cheap. Includes only the non-scoped headline figures safe for any viewer.
import type { AppContext } from '../../src/context.ts'
import { notFound } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('publicReport', (req) => {
    const row = app.byExternalId<Record<string, unknown>>('reports', req.params[app.field('reportId')] ?? '')
    if (!row) return notFound(req)
    const workspace = app.db.get<{ name: string; data_ref: string }>(
      'SELECT name, data_ref FROM tenants WHERE slug = ?', [String(row.tenant_id)],
    )
    return req.json({
      id: row.external_id,
      name: row.name,
      summary: String(row.name ?? ''),
      workspace: workspace?.name ?? '',
      ref: '',
    })
  }, { cache: { queryKeys: [], ttlMs: 30_000 } })
}
