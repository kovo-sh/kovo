// Account search. Filters the acting team's accounts by name and renders an HTML fragment for the SPA
// results pane, echoing the searched term back in the sticky filter control and the results heading.
import { htmlEscape } from '../../../../lib/template.ts'
import type { AppContext, ReqCtx } from '../../src/context.ts'

interface AccountRow { ext_id: string; name: string }

export default function register(app: AppContext): void {
  const qP = app.p('searchQuery')
  app.route('accountSearch', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const term = String(ctx.query[qP] ?? '')
    const rows = app.all<AccountRow>(
      'SELECT ext_id, name FROM accounts WHERE team_id = ? AND name LIKE ?', [ctx.tenant, `%${term}%`])
    const items = rows.map((r) => `<li data-id="${htmlEscape(r.ext_id)}">${htmlEscape(r.name)}</li>`).join('')
    const html =
      `<form class="account-filter"><input name="q" value="${htmlEscape(term)}" /></form>` +
      `<p class="results-banner">Results for ${term} (${rows.length})</p>` +
      `<ul class="account-results">${items}</ul>`
    return ctx.html(html)
  })
}
