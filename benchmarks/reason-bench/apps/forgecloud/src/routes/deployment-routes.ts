// Deployment workflow: submit -> approve -> schedule -> (dispute|reopen) -> release. Scheduling only
// arms the automatic release trigger; a release requires an approved deployment. Reopening clears the
// armed trigger in the neutral implementation. Promotion accepts either an approver session or a
// runner token whose environment scope covers the target environment.
import type { AppContext } from '../context.ts'
import {
  currentUser, currentUserExt, orgOf, unauthorized, forbidden, notFound, invalid, requirePerm,
  can, deploymentView, asRecord, str, audit, nextExternal,
} from '../common.ts'

const ENVS = new Set(['dev', 'staging', 'production', 'prod'])

function normalizeEnv(v: string): string {
  return v === 'prod' ? 'production' : v
}

export function registerDeploymentRoutes(ctx: AppContext): void {
  ctx.route('deployments.list', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const project = str(req.query.project)
    let sql = 'SELECT * FROM deployments WHERE org_slug = ?'
    const params: unknown[] = [org]
    if (project) { sql += ' AND project_ext = ?'; params.push(project) }
    const rows = ctx.db.all<Record<string, unknown>>(sql + ' ORDER BY id', params)
    return req.json({ items: rows.map(deploymentView) })
  })

  ctx.route('deployments.detail', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const ext = req.params[ctx.field('deploymentId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('deployments', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    return req.json({ item: deploymentView(row) })
  })

  ctx.route('deployments.create', (req) => {
    const denied = requirePerm(ctx, req, 'deployment:submit')
    if (denied) return denied
    const org = orgOf(req)!
    const body = asRecord(req.body)
    const env = normalizeEnv(str(body.env) || 'staging')
    if (!ENVS.has(env)) return invalid(req, 'unknown_env')
    const ext = nextExternal(ctx, 'deployments', 'deployment')
    ctx.db.run(
      'INSERT INTO deployments (external_id,org_slug,project_ext,env,version,state,approval_status,requested_by) VALUES (?,?,?,?,?,?,?,?)',
      [ext, org, str(body.project), env, str(body.version) || 'latest', 'pending', 'pending', currentUserExt(ctx, req)],
    )
    audit(ctx, req, 'deployment.submit', ext, env)
    return req.json({ item: deploymentView(ctx.byExternalId<Record<string, unknown>>('deployments', ext)!) }, 201)
  })

  ctx.route('deployments.approve', (req) => {
    const denied = requirePerm(ctx, req, 'deployment:approve')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('deploymentId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('deployments', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    const approver = currentUserExt(ctx, req)
    if (String(row.requested_by) === approver) return forbidden(req)
    if (row.approval_status === 'approved') return req.json({ ok: true, item: deploymentView(row) })
    ctx.db.run("UPDATE deployments SET approval_status = 'approved', approved_by = ?, state = 'approved' WHERE external_id = ? AND org_slug = ?",
      [approver, ext, org])
    audit(ctx, req, 'deployment.approve', ext)
    return req.json({ ok: true })
  })

  ctx.route('deployments.schedule', (req) => {
    const denied = requirePerm(ctx, req, 'deployment:approve')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('deploymentId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('deployments', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    if (row.state === 'released') return invalid(req, 'already_released')
    const body = asRecord(req.body)
    const at = Number(body.scheduledAt) || Date.now() + 3_600_000
    ctx.db.run('UPDATE deployments SET auto_release_scheduled = 1, scheduled_at = ? WHERE external_id = ? AND org_slug = ?',
      [at, ext, org])
    audit(ctx, req, 'deployment.schedule', ext)
    return req.json({ ok: true, autoRelease: true, scheduledAt: at })
  })

  ctx.route('deployments.dispute', (req) => {
    const denied = requirePerm(ctx, req, 'deployment:submit')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('deploymentId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('deployments', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    if (row.state === 'released') return invalid(req, 'already_released')
    // A dispute withdraws approval and disarms any pending automatic release.
    ctx.db.run(
      "UPDATE deployments SET state = 'disputed', approval_status = 'rejected', disputed_at = ?, auto_release_scheduled = 0 WHERE external_id = ? AND org_slug = ?",
      [Date.now(), ext, org],
    )
    audit(ctx, req, 'deployment.dispute', ext)
    return req.json({ ok: true })
  })

  ctx.route('deployments.reopen', (req) => {
    const denied = requirePerm(ctx, req, 'deployment:submit')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('deploymentId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('deployments', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    // Reopening returns the request to review and also disarms a stale automatic release.
    ctx.db.run(
      "UPDATE deployments SET state = 'pending', approval_status = 'pending', auto_release_scheduled = 0 WHERE external_id = ? AND org_slug = ?",
      [ext, org],
    )
    audit(ctx, req, 'deployment.reopen', ext)
    return req.json({ ok: true, item: deploymentView(ctx.byExternalId<Record<string, unknown>>('deployments', ext)!) })
  })

  ctx.route('deployments.release', (req) => {
    const denied = requirePerm(ctx, req, 'deployment:approve')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('deploymentId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('deployments', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    // The manual trigger still honours the approval gate.
    if (row.approval_status !== 'approved') return forbidden(req)
    ctx.db.run("UPDATE deployments SET state = 'released', released_at = ?, auto_release_scheduled = 0 WHERE external_id = ? AND org_slug = ?",
      [Date.now(), ext, org])
    audit(ctx, req, 'deployment.release', ext)
    return req.json({ ok: true, released: ext })
  })

  ctx.route('deployments.promote', (req) => {
    const org = orgOf(req)!
    const ext = req.params[ctx.field('deploymentId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('deployments', ext)
    if (!row) return notFound(req)
    const body = asRecord(req.body)
    const target = normalizeEnv(str(body.targetEnv) || 'production')
    const runner = str(body.runnerToken ?? req.headers['x-runner-token'])
    const user = currentUser(ctx, req)
    if (!user) return unauthorized(req)
    if (runner) {
      const check = ctx.verifyPat(runner)
      // A runner credential only authorizes the environment it was issued for.
      const accepted = check.signatureValid && !check.revoked && check.org === String(row.org_slug) &&
        normalizeEnv(check.envScope) === target
      ctx.recordAuth({
        kind: 'deploy_auth', actorExt: check.userExt ?? '', org: String(row.org_slug), tokenExt: check.row?.external_id ?? '',
        routeKey: 'deployments.promote', accepted, detail: { scope: check.envScope, target },
      })
      if (!accepted) return forbidden(req)
    } else if (!can(ctx, req, 'deployment:approve')) {
      return forbidden(req)
    }
    ctx.db.run("UPDATE deployments SET env = ?, state = 'released', released_at = ?, auto_release_scheduled = 0 WHERE external_id = ? AND org_slug = ?",
      [target, Date.now(), ext, String(row.org_slug)])
    audit(ctx, req, 'deployment.promote', ext, target)
    return req.json({ ok: true, deployment: ext, env: target })
  })
}
