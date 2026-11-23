// Artifact sharing and signed export download. Minting produces an HMAC link for an export path that
// belongs to the caller's organization; fetching verifies the HMAC, the owning organization and the
// storage boundary before reading the virtual object.
import type { AppContext } from '../../src/context.ts'
import {
  asRecord, str, currentUserExt, orgOf, unauthorized, forbidden, notFound, invalid, recordVfsRead,
} from '../../src/common.ts'
import { signLink, signedPath, verifyLink } from '../../src/signed.ts'

function linkFor(app: AppContext, org: string, path: string, artifactId: string): { token: string; path: string; expiresAt: number } {
  const payload = signedPath(org, path, artifactId)
  const token = signLink(payload, app.config.signedUrlSecret)
  const spec = app.plan.routes['artifacts.fetch']
  const base = spec ? spec.path.replace(/:[^/]+$/, '') : '/api/exports/signed/'
  return { token, path: `${base}${encodeURIComponent(token)}`, expiresAt: payload.exp }
}

export default function register(app: AppContext): void {
  app.route('artifacts.mint', (req) => {
    const org = orgOf(req)
    const actor = currentUserExt(app, req)
    if (!org || !actor) return unauthorized(req)
    if (!app.can(actor, org, 'artifact:share')) return forbidden(req)

    const ext = req.params[app.field('artifactId')] ?? ''
    const row = app.byExternalId<Record<string, unknown>>('artifacts', ext)
    if (!row || row.org_slug !== org) return notFound(req)

    const body = asRecord(req.body)
    const requested = str(body.path)
    const stored = String(row.vfs_path)
    const path = requested && requested.startsWith(`/exports/${org}`) ? requested : stored
    return req.json({ link: linkFor(app, org, path, ext) })
  })

  app.route('artifacts.fetch', (req) => {
    const token = req.params[app.field('token')] ?? ''
    const payload = verifyLink(token, app.config.signedUrlSecret)
    if (!payload) return invalid(req, 'invalid_link')
    const org = orgOf(req)
    if (!org || org !== payload.org) return forbidden(req)

    const prefix = `/exports/${payload.org}`
    if (!payload.path.startsWith(prefix)) {
      recordVfsRead(app, req, payload.path, 403, 'outside_export_prefix')
      return forbidden(req)
    }
    const body = app.vfs.read(payload.path)
    recordVfsRead(app, req, payload.path, body === null ? 404 : 200, 'signed_link')
    if (body === null) return notFound(req)
    return req.text(body)
  })
}
