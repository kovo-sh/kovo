// Build detail over a credential presented on the request. The credential's signature, current
// revocation state and organization are all checked before any build record is returned.
import type { AppContext } from '../../src/context.ts'
import { currentUser, orgOf, unauthorized, forbidden, notFound, runView, str } from '../../src/common.ts'

function bearer(headers: Record<string, string | undefined>): string {
  const raw = str(headers.authorization)
  return raw.toLowerCase().startsWith('bearer ') ? raw.slice(7).trim() : ''
}

export default function register(ctx: AppContext): void {
  ctx.route('builds.detail', (req) => {
    const ext = req.params[ctx.field('buildId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('pipeline_runs', ext)
    if (!row) return notFound(req)
    const token = bearer(req.headers as Record<string, string | undefined>)
    if (token) {
      const check = ctx.verifyPat(token)
      if (!check.signatureValid || !check.row?.external_id || check.revoked) return forbidden(req)
      if (check.org && check.org !== String(row.org_slug)) return forbidden(req)
    } else {
      const user = currentUser(ctx, req)
      const org = orgOf(req)
      if (!user || !org) return unauthorized(req)
      if (org !== String(row.org_slug)) return forbidden(req)
    }
    return req.json({ item: runView(row) })
  })
}
