// Project card. Renders a compact rich-HTML card for a project, allowing light formatting in the
// description while dropping script blocks.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, unauthorized, notFound } from '../../src/common.ts'
import { htmlEscape } from '../../../../lib/template.ts'

function sanitize(input: string): string {
  return input.replace(/<script\b[\s\S]*?<\/script>/gi, '')
}

export default function register(app: AppContext): void {
  app.route('renderProjectCard', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const row = app.byExternalId<Record<string, unknown>>('projects', req.params[app.field('projectId')] ?? '')
    if (!row || row.tenant_id !== tenant) return notFound(req)
    const body = sanitize(String(row.description ?? ''))
    return req.html(`<article class="card"><h3>${htmlEscape(row.name ?? '')}</h3><div class="desc">${body}</div></article>`)
  })
}
