// Ticket assignment. Sets the owner of a ticket to a chosen team member (defaulting to the acting
// user). Both the assignee and the target ticket are checked to belong to the acting team before the
// ticket is updated.
import type { AppContext, ReqCtx } from '../../src/context.ts'

interface UserRow { ext_id: string; team_id: string }
interface TicketRow { ext_id: string; team_id: string }

export default function register(app: AppContext): void {
  const idP = app.p('ticketId')
  const userP = app.p('userId')
  app.route('ticketAssign', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const ticketId = ctx.params[idP] ?? ''
    const body = (ctx.body ?? {}) as Record<string, unknown>
    const assignee = String(body[userP] ?? ctx.session.get('userId') ?? '')
    const user = app.get<UserRow>('SELECT ext_id, team_id FROM users WHERE ext_id = ?', [assignee])
    if (!user || user.team_id !== ctx.tenant) return ctx.json({ error: 'invalid_assignee' }, 400)
    const ticket = app.get<TicketRow>('SELECT ext_id, team_id FROM tickets WHERE ext_id = ?', [ticketId])
    if (!ticket || ticket.team_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    app.run('UPDATE tickets SET assignee_id = ? WHERE ext_id = ?', [assignee, ticketId])
    return ctx.json({ ok: true, assignee })
  }, { encoding: 'json' })
}
