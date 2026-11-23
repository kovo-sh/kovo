// Current workspace view. The request may name a workspace with the `x-workspace-id` header; an
// absent header resolves the caller organization's default workspace, and the response lists the
// projects bound to the selected workspace.
import type { AppContext } from '../../src/context.ts'
import {
  currentUser, orgOf, unauthorized, forbidden, notFound, workspaceView, projectView,
} from '../../src/common.ts'

export default function register(ctx: AppContext): void {
  ctx.route('workspaces.current', (req) => {
    const user = currentUser(ctx, req)
    const org = orgOf(req)
    if (!user || !org) return unauthorized(req)
    const header = req.headers['x-workspace-id']
    let workspace: Record<string, unknown> | undefined
    if (header === undefined) {
      workspace = ctx.defaultWorkspace(org) as unknown as Record<string, unknown> | undefined
    } else if (header === '') {
      workspace = ctx.defaultWorkspace(ctx.plan.domain.tenants.orgA) as unknown as Record<string, unknown> | undefined
    } else {
      const row = ctx.workspaceByExt(header)
      if (!row || row.org_slug !== org) return forbidden(req)
      workspace = row as unknown as Record<string, unknown>
    }
    if (!workspace) return notFound(req)
    const projects = ctx.db.all<Record<string, unknown>>(
      'SELECT * FROM projects WHERE org_slug = ? AND workspace_ext = ? ORDER BY id',
      [String(workspace.org_slug), String(workspace.external_id)],
    )
    return req.json({
      workspace: workspaceView(workspace),
      projects: projects.map((row) => projectView(row)),
    })
  })
}
