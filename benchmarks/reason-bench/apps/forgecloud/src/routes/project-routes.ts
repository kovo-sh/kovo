// Projects and pipelines. The neutral defaults scope every read to the caller's org and require the
// matching capability for writes; project transfer authorizes against both the source and destination
// org. A mounted route module may replace any of these handlers.
import type { AppContext } from '../context.ts'
import {
  currentUser, currentUserExt, orgOf, unauthorized, forbidden, notFound, invalid, can, requirePerm,
  projectView, pipelineView, asRecord, str, workspaceFor, nextExternal, audit,
} from '../common.ts'

export function registerProjectRoutes(ctx: AppContext): void {
  ctx.route('projects.list', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const ws = workspaceFor(ctx, req)
    if (ws.error) return ws.error
    const q = req.query
    const state = str(q.state)
    const visibility = str(q.visibility)
    let sql = 'SELECT * FROM projects WHERE org_slug = ?'
    const params: unknown[] = [org]
    if (state) { sql += ' AND state = ?'; params.push(state) }
    if (visibility) { sql += ' AND visibility = ?'; params.push(visibility) }
    const rows = ctx.db.all<Record<string, unknown>>(sql + ' ORDER BY id', params)
    return req.json({ items: rows.map(projectView) })
  })

  ctx.route('projects.create', (req) => {
    const denied = requirePerm(ctx, req, 'project:write')
    if (denied) return denied
    const org = orgOf(req)!
    const body = asRecord(req.body)
    const name = str(body[ctx.field('name')] ?? body.name) || 'untitled'
    const ws = workspaceFor(ctx, req)
    if (ws.error) return ws.error
    const ext = nextExternal(ctx, 'projects', 'project')
    ctx.db.run(
      'INSERT INTO projects (external_id,org_slug,workspace_ext,name,description,visibility,state,owner_ext) VALUES (?,?,?,?,?,?,?,?)',
      [ext, org, String(ws.workspace!.external_id), name, str(body.description), 'private', 'active', currentUserExt(ctx, req)],
    )
    audit(ctx, req, 'project.create', ext, name)
    return req.json({ item: projectView(ctx.byExternalId<Record<string, unknown>>('projects', ext)!) }, 201)
  })

  ctx.route('projects.detail', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const ext = req.params[ctx.field('projectId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('projects', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    return req.json({ item: projectView(row) })
  })

  ctx.route('projects.update', (req) => {
    const denied = requirePerm(ctx, req, 'project:write')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('projectId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('projects', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    const body = asRecord(req.body)
    ctx.db.run(
      'UPDATE projects SET name = ?, description = ?, visibility = ?, state = ? WHERE external_id = ? AND org_slug = ?',
      [str(body.name) || String(row.name), str(body.description) || String(row.description),
        str(body.visibility) || String(row.visibility), str(body.state) || String(row.state), ext, org],
    )
    audit(ctx, req, 'project.update', ext)
    return req.json({ ok: true })
  })

  ctx.route('projects.transfer', (req) => {
    const denied = requirePerm(ctx, req, 'project:transfer')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('projectId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('projects', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    const body = asRecord(req.body)
    const targetRaw = str(body.targetOrg ?? body[ctx.field('orgId')] ?? body.org ?? '')
    const target = ctx.db.get<Record<string, unknown>>(
      'SELECT * FROM orgs WHERE slug = ? OR code = ? OR external_id = ?', [targetRaw, targetRaw, targetRaw])
    if (!target) return invalid(req, 'unknown_target_org')
    if (target.slug === org) return invalid(req, 'same_org')
    const user = currentUserExt(ctx, req)
    // Destructive relocation needs administrative authority on the source and the destination.
    if (!ctx.can(user, org, 'org:admin') || !ctx.can(user, String(target.slug), 'org:admin')) return forbidden(req)
    const destWs = ctx.defaultWorkspace(String(target.slug))
    ctx.db.run('UPDATE projects SET org_slug = ?, workspace_ext = ? WHERE external_id = ? AND org_slug = ?',
      [String(target.slug), String(destWs?.external_id ?? ''), ext, org])
    audit(ctx, req, 'project.transfer', ext, `${org} -> ${target.slug}`)
    return req.json({ ok: true, project: ext, from: org, to: target.slug })
  })

  ctx.route('pipelines.list', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const q = req.query
    const state = str(q.state)
    const visibility = str(q.visibility)
    let sql = 'SELECT * FROM pipelines WHERE org_slug = ?'
    const params: unknown[] = [org]
    // Both filters are applied inside one parenthesized predicate so the OR branch cannot escape the
    // tenant scope.
    if (state || visibility) {
      sql += ' AND ('
      const parts: string[] = []
      if (state) { parts.push('state = ?'); params.push(state) }
      if (visibility) { parts.push('visibility = ?'); params.push(visibility) }
      sql += parts.join(' AND ') + ')'
    }
    const rows = ctx.db.all<Record<string, unknown>>(sql + ' ORDER BY id', params)
    return req.json({ items: rows.map(pipelineView) })
  })

  ctx.route('pipelines.detail', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const ext = req.params[ctx.field('pipelineId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('pipelines', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    return req.json({ item: pipelineView(row) })
  })

  ctx.route('projects.members', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const ext = req.params[ctx.field('projectId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('projects', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    if (!can(ctx, req, 'project:read')) return forbidden(req)
    return req.json({ items: [] })
  })
}
