// Project create. Starts from the caller's default attributes and applies the submitted payload on
// top, then persists the new project.
import type { AppContext } from '../../src/context.ts'
import { identity, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('createProject', (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    const defaults = { tenant_id: id.tenant, owner_id: id.userExtId, visibility: 'private' }
    const row = { ...defaults, ...body }
    const name = String(body[app.field('name')] ?? body.name ?? 'Untitled')
    const ext = app.ids.encode('project', Date.now() % 100000)
    app.db.run(
      'INSERT INTO projects (external_id,tenant_id,owner_id,name,description,visibility) VALUES (?,?,?,?,?,?)',
      [ext, String(row.tenant_id), String(row.owner_id ?? ''), name, String(body.description ?? ''), String(row.visibility ?? 'private')],
    )
    return req.json({ id: ext, name }, 201)
  })
}
