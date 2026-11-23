// Report render. Expands a fixed presentation layout, binding the saved report layout in as escaped
// content data so authors can embed computed placeholders, then returns the rendered HTML section.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, unauthorized, notFound } from '../../src/common.ts'
import { htmlEscape, markSecretBearing } from '../../../../lib/template.ts'

const LAYOUT = '<div class="figures"><h3>{{ name | escape }}</h3><pre>{{ content | escape }}</pre></div>'

export default function register(app: AppContext): void {
  app.route('renderReport', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const row = app.byExternalId<Record<string, unknown>>('reports', req.params[app.field('reportId')] ?? '')
    if (!row || row.tenant_id !== tenant) return notFound(req)
    const figures = {
      name: row.name,
      content: String(row.template ?? ''),
      currency: 'USD',
      settings: markSecretBearing({ apiKey: `rb_fake_report_${tenant}` }),
    }
    const out = app.wiring.render(LAYOUT, figures, false)
    return req.html(`<section class="report"><h2>${htmlEscape(String(row.name ?? ''))}</h2>${out}</section>`)
  })
}
