// Minimal GraphQL endpoint for CI diagnostics. The `ciRun.envPreview` field exposes an environment
// label and a masked preview only; it never returns runner credential material.
import type { AppContext } from '../context.ts'
import { currentUser, orgOf, unauthorized, asRecord, str, maskSecret } from '../common.ts'

interface GraphQLBody { query?: unknown; variables?: unknown }

function fieldArg(query: string, name: string, variables: Record<string, unknown>): string {
  const direct = query.match(new RegExp(`${name}\\s*\\(\\s*id\\s*:\\s*"([^"]+)"\\s*\\)`))
  if (direct) return direct[1]!
  const viaVar = query.match(new RegExp(`${name}\\s*\\(\\s*id\\s*:\\s*\\$([A-Za-z0-9_]+)\\s*\\)`))
  if (viaVar) return str(variables[viaVar[1]!])
  return ''
}

export function registerGraphqlRoutes(ctx: AppContext): void {
  ctx.route('graphql', (req) => {
    const org = orgOf(req)
    const user = currentUser(ctx, req)
    if (!org || !user) return unauthorized(req)
    const body = asRecord(req.body) as GraphQLBody
    const query = str(body.query)
    const variables = asRecord(body.variables)
    if (!query) return req.json({ errors: [{ message: 'query required' }] }, 400)
    const data: Record<string, unknown> = {}

    const runId = fieldArg(query, 'ciRun', variables)
    if (runId) {
      const run = ctx.byExternalId<Record<string, unknown>>('pipeline_runs', runId)
      if (!run || run.org_slug !== org) {
        return req.json({ data: { ciRun: null }, errors: [{ message: 'run not found' }] })
      }
      data.ciRun = {
        id: run.external_id,
        number: run.number,
        state: run.state,
        project: run.project_ext,
        envPreview: {
          env: 'dev',
          token: maskSecret(String(run.env_preview_token)),
          label: `preview:${run.external_id}`,
        },
      }
    }

    const pipelineId = fieldArg(query, 'pipeline', variables)
    if (pipelineId) {
      const row = ctx.byExternalId<Record<string, unknown>>('pipelines', pipelineId)
      data.pipeline = row && row.org_slug === org
        ? { id: row.external_id, name: row.name, state: row.state, visibility: row.visibility }
        : null
    }

    const projectId = fieldArg(query, 'project', variables)
    if (projectId) {
      const row = ctx.byExternalId<Record<string, unknown>>('projects', projectId)
      data.project = row && row.org_slug === org
        ? { id: row.external_id, name: row.name, description: row.description }
        : null
    }

    if (/viewer\s*\{/.test(query)) {
      data.viewer = { id: user.external_id, org, role: ctx.roleFor(user.external_id, org) }
    }
    if (Object.keys(data).length === 0) data.__typename = 'Query'
    return req.json({ data })
  })

  ctx.route('graphql.batch', (req) => {
    const org = orgOf(req)
    const user = currentUser(ctx, req)
    if (!org || !user) return unauthorized(req)
    const body = req.body
    const ops = Array.isArray(body) ? body : [body]
    return req.json({
      data: ops.map((op) => {
        const raw = asRecord(op)
        const query = str(raw.query)
        return query.includes('ciRun') ? { ciRun: null } : { __typename: 'Query' }
      }),
    })
  })
}
