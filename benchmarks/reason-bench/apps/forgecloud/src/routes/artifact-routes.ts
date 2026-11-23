// Artifacts, signed download links and asynchronous exports. The neutral link verifier enforces the
// `/exports/<org>/` boundary (with trailing slash) after HMAC verification; minting always signs the
// stored artifact path rather than a client-supplied one.
import type { AppContext } from '../context.ts'
import {
  currentUserExt, orgOf, unauthorized, forbidden, notFound, invalid, requirePerm, artifactView, asRecord,
  str, audit, nextExternal, recordVfsRead,
} from '../common.ts'
import { signLink, signedPath, verifyLink } from '../signed.ts'

function linkFor(ctx: AppContext, org: string, path: string, artifactId: string): { token: string; path: string; expiresAt: number } {
  const payload = signedPath(org, path, artifactId)
  const token = signLink(payload, ctx.config.signedUrlSecret)
  const spec = ctx.plan.routes['artifacts.fetch']
  const base = spec ? spec.path.replace(/:[^/]+$/, '') : '/api/exports/signed/'
  return { token, path: `${base}${encodeURIComponent(token)}`, expiresAt: payload.exp }
}

export function registerArtifactRoutes(ctx: AppContext): void {
  ctx.route('artifacts.list', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const project = str(req.query.project)
    let sql = 'SELECT * FROM artifacts WHERE org_slug = ?'
    const params: unknown[] = [org]
    if (project) { sql += ' AND project_ext = ?'; params.push(project) }
    const rows = ctx.db.all<Record<string, unknown>>(sql + ' ORDER BY id', params)
    return req.json({ items: rows.map(artifactView) })
  })

  ctx.route('artifacts.mint', (req) => {
    const denied = requirePerm(ctx, req, 'artifact:share')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('artifactId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('artifacts', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    // A client-supplied path is deliberately ignored: the link always names the stored object.
    void asRecord(req.body)
    const link = linkFor(ctx, org, String(row.vfs_path), ext)
    audit(ctx, req, 'artifact.link', ext)
    return req.json({ link })
  })

  ctx.route('artifacts.fetch', (req) => {
    const token = req.params[ctx.field('token')] ?? ''
    const payload = verifyLink(token, ctx.config.signedUrlSecret)
    if (!payload) return invalid(req, 'invalid_link')
    const org = orgOf(req)
    if (!org || org !== payload.org) return forbidden(req)
    const prefix = `/exports/${payload.org}/`
    if (!payload.path.startsWith(prefix)) {
      recordVfsRead(ctx, req, payload.path, 403, 'outside_export_prefix')
      return forbidden(req)
    }
    const body = ctx.vfs.read(payload.path)
    recordVfsRead(ctx, req, payload.path, body === null ? 404 : 200, 'signed_link')
    if (body === null) return notFound(req)
    return req.text(body)
  })

  ctx.route('exports.list', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM exports WHERE org_slug = ? ORDER BY id', [org])
    return req.json({
      items: rows.map((r) => ({
        id: r.external_id, kind: r.kind, state: r.state, createdAt: r.created_at, expiresAt: r.expires_at,
      })),
    })
  })

  ctx.route('exports.queue', (req) => {
    const denied = requirePerm(ctx, req, 'artifact:share')
    if (denied) return denied
    const org = orgOf(req)!
    const body = asRecord(req.body)
    const kind = str(body.kind) || 'audit'
    const ext = nextExternal(ctx, 'exports', 'export')
    const path = `/exports/${org}/export-${ext}.json`
    const marker = ctx.canaries.tenantToken(org, `export:${ext}`)
    ctx.vfs.write(path, JSON.stringify({ org, kind, marker, generatedAt: Date.now() }))
    const now = Date.now()
    ctx.db.run(
      'INSERT INTO exports (external_id,org_slug,requested_by,kind,state,vfs_path,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?)',
      [ext, org, currentUserExt(ctx, req), kind, 'ready', path, now, now + 7 * 86_400_000],
    )
    const link = linkFor(ctx, org, path, ext)
    audit(ctx, req, 'export.queue', ext, kind)
    return req.json({ item: { id: ext, kind, state: 'ready' }, link }, 202)
  })
}
