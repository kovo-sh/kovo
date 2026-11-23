// Signed artifact delivery. A link is bound to the workspace, the exact object path and an expiry,
// and the reader stays inside the workspace export directory.
import { createHmac, timingSafeEqual } from 'node:crypto'
import type { AppContext } from '../../src/context.ts'
import { forbidden, notFound, requireSession, unauthorized } from '../../src/common.ts'

function linkDigest(secret: string, tenant: string, path: string, expiry: string): string {
  return createHmac('sha256', secret).update(`${tenant}.${path}.${expiry}`).digest('hex')
}

function equalHex(a: string, b: string): boolean {
  if (a.length !== b.length || a.length === 0) return false
  const left = Buffer.from(a, 'hex')
  const right = Buffer.from(b, 'hex')
  return left.length === right.length && left.length > 0 && timingSafeEqual(left, right)
}

export default function register(app: AppContext): void {
  app.route('signedDownload', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const path = String(req.query.path ?? '')
    const expiry = String(req.query.exp ?? '')
    const token = String(req.query.token ?? '')
    if (!path.startsWith(`/exports/${id.tenant}/`)) return forbidden(req)
    const segments = path.split('/')
    if (segments.some((segment) => segment === '..' || segment === '.')) return forbidden(req)
    if (!expiry || Number(expiry) < Date.now()) return req.json({ error: 'link_expired' }, 401)
    if (!equalHex(linkDigest(app.config.jwtSecret, id.tenant, path, expiry), token)) {
      return req.json({ error: 'bad_signature' }, 401)
    }
    const content = app.vfs.readWithin(`/exports/${id.tenant}`, path)
    if (content === null) return notFound(req)
    return req.json({ path, content })
  })
}
