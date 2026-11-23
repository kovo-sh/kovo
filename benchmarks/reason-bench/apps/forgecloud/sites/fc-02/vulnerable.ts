// Workspace automations (service accounts). Creating one attaches a role template used by the
// scheduler when the account acts on pipelines. The scheduler accepts a template supplied with the
// request and falls back to the organization administration template when none is given.
import type { AppContext } from '../../src/context.ts'
import {
  asRecord, str, currentUserExt, orgOf, unauthorized, forbidden, nextExternal, audit,
} from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('automations.create', (req) => {
    const org = orgOf(req)
    const actor = currentUserExt(app, req)
    if (!org || !actor) return unauthorized(req)
    if (!app.can(actor, org, 'automation:create')) return forbidden(req)

    const body = asRecord(req.body)
    const requested = str(body.roleTemplate) || str(body[app.field('role')]) || 'admin'
    const name = str(body[app.field('name')] ?? body.name) || `${org}-automation`
    const workspaceRow = app.defaultWorkspace(org)
    const workspace = str(body.workspace) || String(workspaceRow?.external_id ?? '')

    const ext = nextExternal(app, 'automations', 'automation')
    app.db.run(
      'INSERT INTO automations (external_id,org_slug,workspace_ext,name,role_template,created_by) VALUES (?,?,?,?,?,?)',
      [ext, org, workspace, name, requested, actor],
    )
    audit(app, req, 'automation.create', ext, `${name} [${requested}]`)
    return req.json({ item: { id: ext, name, roleTemplate: requested, workspace } }, 201)
  })
}
