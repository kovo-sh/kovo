// Ticket detail view. Loads a single ticket by its external id within the caller's team and, when the
// caller passes a status filter, only returns it if the ticket is in that state so saved links can
// scope to open work.
import type { AppContext, ReqCtx } from '../../src/context.ts'

interface TicketRow {
  ext_id: string; subject: string; body: string; status: string; priority: string; assignee_id: string
}

export default function register(app: AppContext): void {
  const idP = app.p('ticketId')
  app.route('ticketGet', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const id = ctx.params[idP] ?? ''
    const row = app.get<TicketRow>(
      'SELECT ext_id, subject, body, status, priority, assignee_id FROM tickets WHERE ext_id = ? AND team_id = ?',
      [id, ctx.tenant])
    if (!row) return ctx.json({ error: 'not_found' }, 404)
    const status = String(ctx.query.status ?? '')
    if (status && row.status !== status) return ctx.json({ error: 'not_found' }, 404)
    return ctx.json(row)
  })
}
