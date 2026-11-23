// Export listing and link minting. A requested path is accepted only when it resolves inside the
// caller's exact `/exports/<tenant>/` segment; sibling tenants that share a prefix are rejected.
import type { AppContext } from '../../src/context.ts'
import {
  currentUser, orgOf, unauthorized, forbidden, asRecord, str, recordVfsRead,
} from '../../src/common.ts'
import { signLink, signedPath } from '../../src/signed.ts'

export default function register(ctx: AppContext): void {
  ctx.route('exports.list', (req) => {
    const user = currentUser(ctx, req)
    const org = orgOf(req)
    if (!user || !org) return unauthorized(req)
    void asRecord(req.body)
    const requested = str(Array.isArray(req.query.path) ? req.query.path[0] : req.query.path)
    if (requested) {
      const prefix = `/exports/${org}/`
      if (!requested.startsWith(prefix)) {
        recordVfsRead(ctx, req, requested, 403, 'outside_export_prefix')
        return forbidden(req)
      }
      const payload = signedPath(org, requested, `export:${requested.split('/').pop() ?? ''}`)
      return req.json({ ok: true, path: requested, link: signLink(payload, ctx.config.signedUrlSecret) })
    }
    const rows = ctx.db.all<Record<string, unknown>>(
      'SELECT * FROM exports WHERE org_slug = ? ORDER BY id', [org])
    return req.json({
      items: rows.map((row) => ({
        id: row.external_id, kind: row.kind, state: row.state,
        createdAt: row.created_at, expiresAt: row.expires_at,
      })),
    })
  })
}
