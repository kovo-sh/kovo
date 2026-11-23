// Workspace secrets. Single-item mutations and the batch form share the same ownership predicate;
// the batch form validates every id before applying any change. Values are masked in read views.
import type { AppContext } from '../context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'
import {
  currentUser, orgOf, unauthorized, forbidden, notFound, invalid, requirePerm, secretView, asRecord, str, num,
  nextExternal, audit, maskSecret, workspaceFor,
} from '../common.ts'

function workspaceExt(ctx: AppContext, req: ReqCtx): string {
  const ws = workspaceFor(ctx, req)
  return ws.workspace ? String(ws.workspace.external_id) : ''
}

export function registerSecretRoutes(ctx: AppContext): void {
  ctx.route('secrets.list', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const q = req.query
    const project = str(q.project)
    let sql = 'SELECT * FROM secrets WHERE org_slug = ?'
    const params: unknown[] = [org]
    if (project) { sql += ' AND project_ext = ?'; params.push(project) }
    const rows = ctx.db.all<Record<string, unknown>>(sql + ' ORDER BY id', params)
    return req.json({ items: rows.map((r) => secretView(r, false)) })
  })

  ctx.route('secrets.detail', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const ext = req.params[ctx.field('secretId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('secrets', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    const reveal = str(req.query.reveal) === '1' && ctx.can(currentUser(ctx, req)?.external_id ?? '', org, 'secret:read')
    return req.json({ item: secretView(row, reveal) })
  })

  ctx.route('secrets.create', (req) => {
    const denied = requirePerm(ctx, req, 'secret:write')
    if (denied) return denied
    const org = orgOf(req)!
    const body = asRecord(req.body)
    const name = str(body[ctx.field('name')] ?? body.name) || 'unnamed'
    const value = str(body.value) || `rbs_${org.replace(/[^a-z0-9]/gi, '').slice(0, 6)}_${ctx.plan.canarySalt.slice(0, 10)}`
    const ext = nextExternal(ctx, 'secrets', 'secret')
    ctx.db.run(
      'INSERT INTO secrets (external_id,org_slug,workspace_ext,project_ext,name,value,kind,version) VALUES (?,?,?,?,?,?,?,?)',
      [ext, org, workspaceExt(ctx, req), str(body.project), `${org}/${name}`, value, str(body.kind) || 'opaque', 1],
    )
    audit(ctx, req, 'secret.create', ext, name)
    return req.json({ item: secretView(ctx.byExternalId<Record<string, unknown>>('secrets', ext)!, true) }, 201)
  })

  ctx.route('secrets.update', (req) => {
    const denied = requirePerm(ctx, req, 'secret:write')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('secretId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('secrets', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    const body = asRecord(req.body)
    const nextValue = body.value !== undefined ? str(body.value) : String(row.value)
    const version = num(body.version) || Number(row.version) + 1
    ctx.db.run('UPDATE secrets SET name = ?, value = ?, version = ? WHERE external_id = ? AND org_slug = ?',
      [str(body.name) || String(row.name), nextValue, version, ext, org])
    audit(ctx, req, 'secret.update', ext)
    return req.json({ item: secretView(ctx.byExternalId<Record<string, unknown>>('secrets', ext)!, false) })
  })

  ctx.route('secrets.delete', (req) => {
    const denied = requirePerm(ctx, req, 'secret:write')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('secretId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('secrets', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    ctx.db.run('DELETE FROM secrets WHERE external_id = ? AND org_slug = ?', [ext, org])
    audit(ctx, req, 'secret.delete', ext)
    return req.json({ ok: true })
  })

  ctx.route('secrets.batch', (req) => {
    const denied = requirePerm(ctx, req, 'secret:write')
    if (denied) return denied
    const org = orgOf(req)!
    const body = asRecord(req.body)
    const rawIds = body.ids ?? body.secretIds ?? body[ctx.field('secretId') + 's']
    const ids = Array.isArray(rawIds) ? rawIds.map(String).filter(Boolean) : []
    if (ids.length === 0) return invalid(req, 'ids_required')
    const rows = ids.map((id) => ctx.byExternalId<Record<string, unknown>>('secrets', id))
    // Every element must belong to the caller's org before any element is changed.
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i]
      if (!row) return notFound(req)
      if (row.org_slug !== org) return forbidden(req)
    }
    const patch = asRecord(body.patch)
    const value = body.value !== undefined ? str(body.value) : undefined
    const name = body.name !== undefined ? str(body.name) : undefined
    for (const row of rows) {
      const nextName = name ?? (str(patch.name) || String(row!.name))
      const nextValue = value ?? (patch.value !== undefined ? str(patch.value) : String(row!.value))
      ctx.db.run('UPDATE secrets SET name = ?, value = ?, version = version + 1 WHERE external_id = ? AND org_slug = ?',
        [nextName, nextValue, String(row!.external_id), org])
    }
    audit(ctx, req, 'secret.batch', ids.join(','), `count=${ids.length}`)
    const updated = ids.map((id) => ctx.byExternalId<Record<string, unknown>>('secrets', id)!)
    return req.json({ ok: true, items: updated.map((r) => secretView(r, false)), masked: updated.map((r) => maskSecret(String(r.value))) })
  })
}
