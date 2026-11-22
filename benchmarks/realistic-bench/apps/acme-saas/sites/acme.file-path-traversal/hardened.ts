// File download. Serves a file from the caller tenant's storage area, reducing the request to a bare
// filename so it can never climb out of the tenant jail.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, unauthorized, notFound } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('downloadFile', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const rel = String(req.query[app.field('filePath')] ?? '').replace(/^\/+/, '')
    const name = rel.split(/[\\/]/).pop() ?? ''
    if (!name || name.includes('..')) return notFound(req)
    const content = app.vfs.read(`/tenants/${tenant}/files/${name}`)
    if (content == null) return notFound(req)
    return req.text(content)
  })
}
