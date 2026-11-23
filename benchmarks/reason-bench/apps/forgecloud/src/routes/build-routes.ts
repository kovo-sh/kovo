// Build (pipeline run) surface. Reads are org-scoped; log access resolves the seeded virtual log
// file only for a run in the caller's org. Cancelling a run requires the build capability.
import type { AppContext } from '../context.ts'
import {
  orgOf, unauthorized, forbidden, notFound, requirePerm, runView, str, audit,
} from '../common.ts'

export function registerBuildRoutes(ctx: AppContext): void {
  ctx.route('builds.list', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const q = req.query
    const pipeline = str(q.pipeline)
    const project = str(q.project)
    let sql = 'SELECT * FROM pipeline_runs WHERE org_slug = ?'
    const params: unknown[] = [org]
    if (pipeline) { sql += ' AND pipeline_ext = ?'; params.push(pipeline) }
    if (project) { sql += ' AND project_ext = ?'; params.push(project) }
    const rows = ctx.db.all<Record<string, unknown>>(sql + ' ORDER BY id DESC LIMIT 100', params)
    return req.json({ items: rows.map(runView) })
  })

  ctx.route('builds.detail', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const ext = req.params[ctx.field('buildId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('pipeline_runs', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    return req.json({ item: runView(row) })
  })

  ctx.route('builds.logs', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const ext = req.params[ctx.field('buildId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('pipeline_runs', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    if (row.state === 'running') {
      return req.json({ lines: ['build in progress', 'waiting for runner output'] })
    }
    const text = ctx.vfs.read(String(row.log_path)) ?? ''
    return req.json({ lines: text.split('\n').filter(Boolean) })
  })

  ctx.route('builds.cancel', (req) => {
    const denied = requirePerm(ctx, req, 'build:run')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('buildId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('pipeline_runs', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    if (row.state === 'queued' || row.state === 'running') {
      ctx.db.run("UPDATE pipeline_runs SET state = 'cancelled' WHERE external_id = ? AND org_slug = ?", [ext, org])
      audit(ctx, req, 'build.cancel', ext)
    } else {
      return forbidden(req)
    }
    return req.json({ ok: true })
  })
}
