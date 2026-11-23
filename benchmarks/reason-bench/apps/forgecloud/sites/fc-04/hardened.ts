// Pipeline list. Supports the console's state and visibility filters; both filters are translated
// into predicate fragments over the tenant-scoped base query. Each row carries its project's short
// note so the console can render the pipeline card without a second round trip.
import type { AppContext } from '../../src/context.ts'
import { orgOf, unauthorized, str } from '../../src/common.ts'

function view(app: AppContext, row: Record<string, unknown>): Record<string, unknown> {
  const project = app.byExternalId<Record<string, unknown>>('projects', String(row.project_ext))
  return {
    id: row.external_id, name: row.name, project: row.project_ext, state: row.state,
    visibility: row.visibility, runner: row.runner, org: row.org_slug,
    projectNote: project ? project.description : '',
  }
}

export default function register(app: AppContext): void {
  app.route('pipelines.list', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const state = str(req.query.state)
    const visibility = str(req.query.visibility)
    let sql = 'SELECT * FROM pipelines WHERE org_slug = ?'
    const params: unknown[] = [org]
    if (state && visibility) {
      sql += ' AND (state = ? AND visibility = ?)'
      params.push(state, visibility)
    } else if (state) {
      sql += ' AND state = ?'
      params.push(state)
    } else if (visibility) {
      sql += ' AND visibility = ?'
      params.push(visibility)
    }
    const rows = app.db.all<Record<string, unknown>>(sql + ' ORDER BY id', params)
    return req.json({ items: rows.map((row) => view(app, row)) })
  })
}
