// Project update. A request that names a destination organization relocates the row only when the
// caller holds administrative authority in both the current and the destination organization.
import type { AppContext } from '../../src/context.ts'
import {
  currentUser, currentUserExt, orgOf, unauthorized, forbidden, notFound, invalid, can,
  projectView, asRecord, str, audit,
} from '../../src/common.ts'

function orgByParam(ctx: AppContext, value: string): Record<string, unknown> | undefined {
  return ctx.db.get<Record<string, unknown>>(
    'SELECT * FROM orgs WHERE slug = ? OR code = ? OR external_id = ?', [value, value, value])
}

export default function register(ctx: AppContext): void {
  ctx.route('projects.update', (req) => {
    const user = currentUser(ctx, req)
    const org = orgOf(req)
    if (!user || !org) return unauthorized(req)
    const ext = req.params[ctx.field('projectId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('projects', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    const body = asRecord(req.body)
    const targetRaw = str(body.targetOrg ?? body[ctx.field('orgId')] ?? body.org)
    if (targetRaw) {
      const target = orgByParam(ctx, targetRaw)
      if (!target) return invalid(req, 'unknown_target_org')
      if (target.slug === org) return invalid(req, 'same_org')
      if (!can(ctx, req, 'org:admin')) return forbidden(req)
      if (!ctx.can(user.external_id, String(target.slug), 'org:admin')) return forbidden(req)
      const destination = ctx.defaultWorkspace(String(target.slug))
      ctx.db.run('UPDATE projects SET org_slug = ?, workspace_ext = ? WHERE external_id = ? AND org_slug = ?',
        [String(target.slug), String(destination?.external_id ?? ''), ext, org])
      audit(ctx, req, 'project.transfer', ext, `${org} -> ${target.slug}`)
      return req.json({ ok: true, project: ext, from: org, to: target.slug })
    }
    ctx.db.run(
      'UPDATE projects SET name = ?, description = ?, visibility = ?, state = ? WHERE external_id = ? AND org_slug = ?',
      [str(body.name) || String(row.name), str(body.description) || String(row.description),
        str(body.visibility) || String(row.visibility), str(body.state) || String(row.state), ext, org],
    )
    audit(ctx, req, 'project.update', ext, currentUserExt(ctx, req))
    return req.json({ ok: true, item: projectView(ctx.byExternalId<Record<string, unknown>>('projects', ext)!) })
  })
}
