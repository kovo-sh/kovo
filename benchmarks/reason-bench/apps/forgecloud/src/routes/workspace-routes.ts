// Organization and workspace surface. Workspace selection honours the `x-workspace-id` header and
// validates the workspace against the caller's org; an absent header resolves the org default.
import type { AppContext } from '../context.ts'
import {
  currentUser, orgOf, unauthorized, notFound, forbidden, workspaceView, workspaceFor, asRecord,
} from '../common.ts'

export function registerWorkspaceRoutes(ctx: AppContext): void {
  ctx.route('orgs.list', (req) => {
    const u = currentUser(ctx, req)
    if (!u) return unauthorized(req)
    const rows = ctx.db.all<{
      external_id: string; code: string; slug: string; name: string; plan: string; role: string
    }>(
      `SELECT o.external_id, o.code, o.slug, o.name, o.plan, m.role
         FROM memberships m JOIN orgs o ON o.slug = m.org_slug
        WHERE m.user_ext_id = ? ORDER BY o.id`,
      [u.external_id],
    )
    return req.json({ items: rows, active: orgOf(req) })
  })

  ctx.route('workspaces.list', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const q = req.query
    const visibility = typeof q.visibility === 'string' ? q.visibility : ''
    let rows = ctx.db.all<Record<string, unknown>>(
      'SELECT * FROM workspaces WHERE org_slug = ? ORDER BY id', [org])
    if (visibility) rows = rows.filter((r) => r.visibility === visibility)
    return req.json({ items: rows.map(workspaceView) })
  })

  ctx.route('workspaces.current', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const resolved = workspaceFor(ctx, req)
    if (resolved.error) return resolved.error
    const ws = resolved.workspace!
    const body = asRecord(req.body)
    if (body.name !== undefined) {
      if (!ctx.can(currentUser(ctx, req)?.external_id ?? '', org, 'project:write')) return forbidden(req)
      ctx.db.run('UPDATE workspaces SET name = ? WHERE external_id = ? AND org_slug = ?',
        [String(body.name), String(ws.external_id), org])
      return req.json({ ok: true })
    }
    return req.json({ workspace: workspaceView(ws) })
  })

  ctx.route('workspaces.detail', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const ext = req.params[ctx.field('workspaceId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('workspaces', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    return req.json(workspaceView(row))
  })
}
