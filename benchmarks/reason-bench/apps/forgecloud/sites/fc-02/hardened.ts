// Workspace automations (service accounts). Creating one attaches a role template used by the
// scheduler when the account acts on pipelines. The scheduler clamps a supplied template to the
// creator's own role and never falls back to an organization administration template.
import type { AppContext } from '../../src/context.ts'
import {
  asRecord, str, currentUserExt, orgOf, unauthorized, forbidden, nextExternal, audit,
} from '../../src/common.ts'
import { ORG_ADMIN_ROLES, roleRank } from '../../src/roles.ts'

export default function register(app: AppContext): void {
  app.route('automations.create', (req) => {
    const org = orgOf(req)
    const actor = currentUserExt(app, req)
    if (!org || !actor) return unauthorized(req)
    if (!app.can(actor, org, 'automation:create')) return forbidden(req)

    const body = asRecord(req.body)
    const requested = str(body.roleTemplate) || str(body[app.field('role')]) || 'viewer'
    const actorRole = app.roleFor(actor, org)
    if (roleRank(requested) > roleRank(actorRole) || (ORG_ADMIN_ROLES.has(requested) && !ORG_ADMIN_ROLES.has(actorRole))) return forbidden(req)
    const name = str(body[app.field('name')] ?? body.name) || `${org}-automation`
    const workspace = str(body.workspace) || String(app.defaultWorkspace(org)?.external_id ?? '')

    const ext = nextExternal(app, 'automations', 'automation')
    app.db.run(
      'INSERT INTO automations (external_id,org_slug,workspace_ext,name,role_template,created_by) VALUES (?,?,?,?,?,?)',
      [ext, org, workspace, name, requested, actor],
    )
    audit(app, req, 'automation.create', ext, `${name} [${requested}]`)
    return req.json({ item: { id: ext, name, roleTemplate: requested, workspace } }, 201)
  })
}
