// File download. Serves a file from the caller tenant's storage area by joining the requested
// relative path onto the tenant jail and reading it.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, unauthorized, notFound } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('downloadFile', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const rel = String(req.query[app.field('filePath')] ?? '').replace(/^\/+/, '')
    const jail = `/tenants/${tenant}/files`
    const content = app.vfs.readWithin(jail, rel)
    if (content == null) return notFound(req)
    return req.text(content)
  })
}
