// Teams and workspace automations (service accounts). Creating an automation can attach a role
// template; the neutral path clamps that template to the creator's own role rank and never grants
// organization administration implicitly.
import type { AppContext } from '../context.ts'
import {
  currentUserExt, orgOf, unauthorized, forbidden, notFound, invalid, requirePerm, asRecord, str,
  nextExternal, audit, roleOf,
} from '../common.ts'
import { roleRank, ORG_ADMIN_ROLES } from '../roles.ts'

export function registerAutomationRoutes(ctx: AppContext): void {
  ctx.route('teams.list', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM teams WHERE org_slug = ? ORDER BY id', [org])
    return req.json({
      items: rows.map((r) => ({
        id: r.external_id, name: r.name, roleTemplate: r.role_template,
        members: ctx.db.all<{ user_ext_id: string; role: string }>(
          'SELECT user_ext_id, role FROM team_members WHERE team_ext_id = ?', [String(r.external_id)]),
      })),
    })
  })

  ctx.route('teams.create', (req) => {
    const denied = requirePerm(ctx, req, 'team:manage')
    if (denied) return denied
    const org = orgOf(req)!
    const body = asRecord(req.body)
    const name = str(body.name) || 'new-team'
    const role = str(body.roleTemplate) || 'developer'
    if (roleRank(role) > roleRank(roleOf(ctx, req))) return forbidden(req)
    const ext = nextExternal(ctx, 'teams', 'team')
    ctx.db.run('INSERT INTO teams (external_id,org_slug,name,role_template) VALUES (?,?,?,?)', [ext, org, name, role])
    audit(ctx, req, 'team.create', ext, name)
    return req.json({ item: { id: ext, name, roleTemplate: role } }, 201)
  })

  ctx.route('teams.addMember', (req) => {
    const denied = requirePerm(ctx, req, 'team:manage')
    if (denied) return denied
    const org = orgOf(req)!
    const teamExt = req.params[ctx.field('teamId')] ?? ''
    const team = ctx.byExternalId<Record<string, unknown>>('teams', teamExt)
    if (!team || team.org_slug !== org) return notFound(req)
    const body = asRecord(req.body)
    const memberExt = str(body.memberId ?? body.userId)
    const user = ctx.db.get<{ id: number }>('SELECT id FROM users WHERE external_id = ?', [memberExt])
    if (!user) return notFound(req)
    if (!ctx.membershipFor(memberExt, org)) return invalid(req, 'not_a_member')
    ctx.db.run('INSERT INTO team_members (team_ext_id,org_slug,user_ext_id,role) VALUES (?,?,?,?)',
      [teamExt, org, memberExt, str(body.role) || 'developer'])
    audit(ctx, req, 'team.add_member', teamExt, memberExt)
    return req.json({ ok: true })
  })

  ctx.route('automations.list', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM automations WHERE org_slug = ? ORDER BY id', [org])
    return req.json({
      items: rows.map((r) => ({
        id: r.external_id, name: r.name, roleTemplate: r.role_template, workspace: r.workspace_ext,
      })),
    })
  })

  ctx.route('automations.create', (req) => {
    const denied = requirePerm(ctx, req, 'automation:create')
    if (denied) return denied
    const org = orgOf(req)!
    const body = asRecord(req.body)
    const requested = str(body.roleTemplate) || 'viewer'
    const actorRole = roleOf(ctx, req)
    if (ORG_ADMIN_ROLES.has(requested) && !ORG_ADMIN_ROLES.has(actorRole)) return forbidden(req)
    if (roleRank(requested) > roleRank(actorRole)) return forbidden(req)
    const ext = nextExternal(ctx, 'automations', 'automation')
    const name = str(body.name) || `${org}-automation`
    const workspace = str(body.workspace) || String(ctx.defaultWorkspace(org)?.external_id ?? '')
    ctx.db.run(
      'INSERT INTO automations (external_id,org_slug,workspace_ext,name,role_template,created_by) VALUES (?,?,?,?,?,?)',
      [ext, org, workspace, name, requested, currentUserExt(ctx, req)],
    )
    audit(ctx, req, 'automation.create', ext, `${name} [${requested}]`)
    return req.json({ item: { id: ext, name, roleTemplate: requested } }, 201)
  })
}
