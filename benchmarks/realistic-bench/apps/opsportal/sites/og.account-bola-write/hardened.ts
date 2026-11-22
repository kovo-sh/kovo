// Account update. Patches a single editable attribute on an account. The handler confirms the loaded
// record belongs to the acting org before writing so the edit stays inside the acting team.
import type { AppContext, ReqCtx } from '../../src/context.ts'

const EDITABLE = new Set(['name', 'tier', 'owner_email', 'notes'])

interface AccountRow { ext_id: string; team_id: string }

export default function register(app: AppContext): void {
  const idP = app.p('accountId')
  const fieldP = app.p('accountField')
  app.route('accountUpdate', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const id = ctx.params[idP] ?? ''
    const body = (ctx.body ?? {}) as Record<string, unknown>
    const row = app.get<AccountRow>('SELECT ext_id, team_id FROM accounts WHERE ext_id = ?', [id])
    if (!row) return ctx.json({ error: 'not_found' }, 404)
    if (row.team_id !== ctx.tenant) return ctx.json({ error: 'forbidden' }, 403)
    const field = String(body[fieldP] ?? 'name')
    const col = EDITABLE.has(field) ? field : 'name'
    const value = String(body.value ?? '')
    app.run(`UPDATE accounts SET ${col} = ? WHERE ext_id = ?`, [value, id])
    return ctx.json({ ok: true, id })
  }, { encoding: 'json' })
}
