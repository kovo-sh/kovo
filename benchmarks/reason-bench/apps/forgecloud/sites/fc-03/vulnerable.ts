// Project relocation between organizations. The caller selects the working organization with the
// org header, so the route authorizes the request against the project's current organization and the
// organization that will receive it. Relocation rewrites the owning org and the default workspace.
import type { AppContext } from '../../src/context.ts'
import {
  asRecord, str, currentUserExt, orgOf, unauthorized, forbidden, notFound, invalid, audit,
} from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('projects.transfer', (req) => {
    const org = orgOf(req)
    const actor = currentUserExt(app, req)
    if (!org || !actor) return unauthorized(req)

    const ext = req.params[app.field('projectId')] ?? ''
    const row = app.byExternalId<Record<string, unknown>>('projects', ext)
    if (!row || row.org_slug !== org) return notFound(req)

    const body = asRecord(req.body)
    const targetRaw = str(body.targetOrg ?? body[app.field('orgId')] ?? body.org)
    const target = app.db.get<Record<string, unknown>>(
      'SELECT * FROM orgs WHERE slug = ? OR code = ? OR external_id = ?', [targetRaw, targetRaw, targetRaw])
    if (!target) return invalid(req, 'unknown_target_org')
    if (target.slug === org) return invalid(req, 'same_org')

    // Source participation and destination administration are both required.
    if (!app.membershipFor(actor, org)) return forbidden(req)
    if (!app.can(actor, String(target.slug), 'org:admin')) return forbidden(req)

    const destWorkspace = app.defaultWorkspace(String(target.slug))
    app.db.run('UPDATE projects SET org_slug = ?, workspace_ext = ? WHERE external_id = ? AND org_slug = ?',
      [String(target.slug), String(destWorkspace?.external_id ?? ''), ext, org])
    audit(app, req, 'project.transfer', ext, `${org} -> ${String(target.slug)}`)
    return req.json({ ok: true, project: ext, from: org, to: target.slug })
  })
}
