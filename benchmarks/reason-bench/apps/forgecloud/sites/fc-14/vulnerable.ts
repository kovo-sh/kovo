// Deployment review window. Reopening a request returns it to review, and a release honours either
// an explicit approval or an armed automatic trigger whose scheduled time has arrived.
import type { AppContext } from '../../src/context.ts'
import {
  currentUser, currentUserExt, orgOf, unauthorized, forbidden, notFound, requirePerm,
  deploymentView, audit,
} from '../../src/common.ts'

export default function register(ctx: AppContext): void {
  ctx.route('deployments.reopen', (req) => {
    const denied = requirePerm(ctx, req, 'deployment:submit')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('deploymentId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('deployments', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    ctx.db.run(
      "UPDATE deployments SET state = 'pending', approval_status = 'pending' WHERE external_id = ? AND org_slug = ?",
      [ext, org],
    )
    audit(ctx, req, 'deployment.reopen', ext, currentUserExt(ctx, req))
    return req.json({ ok: true, item: deploymentView(ctx.byExternalId<Record<string, unknown>>('deployments', ext)!) })
  })

  ctx.route('deployments.release', (req) => {
    const denied = requirePerm(ctx, req, 'deployment:approve')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('deploymentId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('deployments', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    const armed = Number(row.auto_release_scheduled) === 1 && Number(row.scheduled_at) <= Date.now()
    if (!armed && row.approval_status !== 'approved') return forbidden(req)
    ctx.db.run("UPDATE deployments SET state = 'released', released_at = ?, auto_release_scheduled = 0 WHERE external_id = ? AND org_slug = ?",
      [Date.now(), ext, org])
    audit(ctx, req, 'deployment.release', ext, currentUserExt(ctx, req))
    return req.json({ ok: true, released: ext })
  })
}
