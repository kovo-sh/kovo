// Ticket notes: a note is stored on write and the ticket viewer renders stored notes, escaping markup
// so agents can include angle brackets in their escalation context without breaking the layout.
import { htmlEscape } from '../../../../lib/template.ts'
import type { AppContext, ReqCtx } from '../../src/context.ts'

interface NoteRow { body: string }

export default function register(app: AppContext): void {
  const idP = app.p('ticketId')
  const noteP = app.p('noteBody')

  app.route('ticketNoteCreate', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const ticket = ctx.params[idP] ?? ''
    const note = String((ctx.body as Record<string, unknown>)[noteP] ?? '')
    app.run(
      'INSERT INTO ticket_notes(ticket_id, team_id, author, body, created_at) VALUES (?,?,?,?,?)',
      [ticket, ctx.tenant, ctx.actor, note, Date.now()],
    )
    return ctx.json({ ok: true })
  }, { encoding: 'json' })

  app.route('ticketView', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const ticket = ctx.params[idP] ?? ''
    const notes = app.all<NoteRow>(
      'SELECT body FROM ticket_notes WHERE ticket_id = ? AND team_id = ? ORDER BY id', [ticket, ctx.tenant])
    const rows = notes.map((n) => `<div class="note">${htmlEscape(n.body)}</div>`).join('')
    return ctx.html(`<section class="ticket-notes">${rows}</section>`)
  })
}
