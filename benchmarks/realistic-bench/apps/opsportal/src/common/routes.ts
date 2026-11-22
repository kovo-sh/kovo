// Common, tenant-scoped read endpoints the SPA uses but which are not planted sites: health, the UI
// config document, dashboard summary, and the standard list/detail views. All results are filtered to
// the acting tenant so they carry no foreign canaries.
import type { AppContext, ReqCtx } from '../context.ts'

const UI_ROUTES = [
  'login', 'logout', 'me', 'csrf', 'dashboardSummary', 'graphql', 'ticketList', 'ticketView',
  'ticketNoteCreate', 'accountList', 'accountGet', 'reportList', 'reportRender', 'searchList',
  'logList', 'logView', 'jobList', 'webhookList', 'integrationList', 'flagList', 'diagRun',
]

export function registerCommon(app: AppContext): void {

  const need = (ctx: ReqCtx): boolean => ctx.actor !== 'anonymous'

  app.route('health', (ctx: ReqCtx) => ctx.json({ status: 'ok', app: 'opsportal' }))

  app.route('appConfig', (ctx: ReqCtx) => {
    const routes: Record<string, { method: string; path: string }> = {}
    for (const key of UI_ROUTES) {
      const r = app.plan.routes[key]
      if (r) routes[key] = { method: r.method, path: r.path }
    }
    const params: Record<string, string> = {}
    for (const key of ['templateSrc', 'host', 'noteBody', 'searchQuery', 'logName']) params[key] = app.p(key)
    return ctx.json({ apiPrefix: app.plan.apiPrefix, idFormat: app.plan.idFormat, routes, params })
  })

  app.route('dashboardSummary', (ctx: ReqCtx) => {
    if (!need(ctx)) return ctx.json({ error: 'auth_required' }, 401)
    const tickets = app.all('SELECT ext_id, subject, status FROM tickets WHERE team_id = ?', [ctx.tenant])
    const accounts = app.all('SELECT ext_id, name FROM accounts WHERE team_id = ?', [ctx.tenant])
    return ctx.json({ tenant: ctx.tenant, openTickets: tickets.length, accounts: accounts.length })
  })

  const listScoped = (table: string, cols: string) => (ctx: ReqCtx) => {
    if (!need(ctx)) return ctx.json({ error: 'auth_required' }, 401)
    return ctx.json({ items: app.all(`SELECT ${cols} FROM ${table} WHERE team_id = ?`, [ctx.tenant]) })
  }

  app.route('ticketList', listScoped('tickets', 'ext_id, subject, status, account_id'))
  app.route('accountList', listScoped('accounts', 'ext_id, name, tier'))
  app.route('reportList', listScoped('reports', 'ext_id, name'))
  app.route('searchList', listScoped('saved_searches', 'ext_id, name, query'))
  app.route('jobList', listScoped('jobs', 'ext_id, name, status'))
  app.route('webhookList', listScoped('webhook_targets', 'ext_id, name, url'))
  app.route('flagList', listScoped('feature_flags', 'ext_id, flag_key, value'))
  app.route('auditList', listScoped('audit_events', 'ext_id, actor, action'))

  app.route('accountGet', (ctx: ReqCtx) => {
    if (!need(ctx)) return ctx.json({ error: 'auth_required' }, 401)
    const row = app.get('SELECT ext_id, name, tier, owner_email FROM accounts WHERE ext_id = ? AND team_id = ?',
      [ctx.params[app.p('accountId')], ctx.tenant])
    return row ? ctx.json(row) : ctx.json({ error: 'not_found' }, 404)
  })

  app.route('logList', (ctx: ReqCtx) => {
    if (!need(ctx)) return ctx.json({ error: 'auth_required' }, 401)
    return ctx.json({ files: app.vfs.list(app.logRoot) })
  })
}
