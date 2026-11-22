// Project create. Builds the new project from named fields only, with the owning tenant and owner
// taken from the caller session, then persists it.
import type { AppContext } from '../../src/context.ts'
import { identity, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('createProject', (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    const name = String(body[app.field('name')] ?? body.name ?? 'Untitled')
    const visibility = body.visibility === 'internal' ? 'internal' : 'private'
    const ext = app.ids.encode('project', Date.now() % 100000)
    app.db.run(
      'INSERT INTO projects (external_id,tenant_id,owner_id,name,description,visibility) VALUES (?,?,?,?,?,?)',
      [ext, id.tenant, id.userExtId, name, String(body.description ?? ''), visibility],
    )
    return req.json({ id: ext, name }, 201)
  })
}
