// CI diagnostics and deployment promotion. The diagnostics query returns a masked environment preview
// for the caller's organization, and promotion accepts a runner credential only when its environment
// scope covers the requested environment.
import type { AppContext } from '../../src/context.ts'
import {
  currentUser, currentUserExt, orgOf, unauthorized, forbidden, notFound, can, asRecord, str,
  audit, maskSecret,
} from '../../src/common.ts'

function fieldArg(query: string, name: string, variables: Record<string, unknown>): string {
  const direct = query.match(new RegExp(`${name}\\s*\\(\\s*id\\s*:\\s*"([^"]+)"\\s*\\)`))
  if (direct) return direct[1]!
  const viaVar = query.match(new RegExp(`${name}\\s*\\(\\s*id\\s*:\\s*\\$([A-Za-z0-9_]+)\\s*\\)`))
  if (viaVar) return str(variables[viaVar[1]!])
  return ''
}

function normalizeEnv(value: string): string {
  return value === 'prod' ? 'production' : value
}

export default function register(ctx: AppContext): void {
  ctx.route('graphql', (req) => {
    const org = orgOf(req)
    const user = currentUser(ctx, req)
    if (!org || !user) return unauthorized(req)
    const body = asRecord(req.body)
    const query = str(body.query)
    const variables = asRecord(body.variables)
    if (!query) return req.json({ errors: [{ message: 'query required' }] }, 400)
    const runId = fieldArg(query, 'ciRun', variables)
    if (!runId) return req.json({ data: { __typename: 'Query' } })
    const run = ctx.byExternalId<Record<string, unknown>>('pipeline_runs', runId)
    if (!run || run.org_slug !== org) {
      return req.json({ data: { ciRun: null }, errors: [{ message: 'run not found' }] })
    }
    return req.json({
      data: {
        ciRun: {
          id: run.external_id,
          number: run.number,
          state: run.state,
          project: run.project_ext,
          envPreview: {
            env: 'dev',
            token: maskSecret(String(run.env_preview_token)),
            label: `preview:${run.external_id}`,
          },
        },
      },
    })
  })

  ctx.route('deployments.promote', (req) => {
    const user = currentUser(ctx, req)
    const org = orgOf(req)
    if (!user || !org) return unauthorized(req)
    const ext = req.params[ctx.field('deploymentId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('deployments', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    const body = asRecord(req.body)
    const target = normalizeEnv(str(body.targetEnv) || 'production')
    const runner = str(body.runnerToken ?? req.headers['x-runner-token'])
    if (runner) {
      const run = ctx.db.get<Record<string, unknown>>(
        'SELECT * FROM pipeline_runs WHERE env_preview_token = ? AND org_slug = ?', [runner, org])
      const check = ctx.verifyPat(runner)
      const scope = run ? 'dev' : check.envScope
      const acceptedByRow = !!run && run.org_slug === org && normalizeEnv(scope) === target
      const acceptedByPat = check.signatureValid && !check.revoked && check.org === org &&
        normalizeEnv(check.envScope) === target
      const accepted = acceptedByRow || acceptedByPat
      ctx.recordAuth({
        kind: 'deploy_auth', actorExt: currentUserExt(ctx, req), org,
        tokenExt: check.row?.external_id ?? '', routeKey: 'deployments.promote',
        accepted, detail: { scope, target },
      })
      if (!accepted) return forbidden(req)
    } else if (!can(ctx, req, 'deployment:approve')) {
      return forbidden(req)
    }
    ctx.db.run("UPDATE deployments SET env = ?, state = 'released', released_at = ?, auto_release_scheduled = 0 WHERE external_id = ? AND org_slug = ?",
      [target, Date.now(), ext, org])
    audit(ctx, req, 'deployment.promote', ext, target)
    return req.json({ ok: true, deployment: ext, env: target })
  })
}
