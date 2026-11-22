// Profile update: applies a member's self-service profile patch to their own account record.
import type { AppContext, ReqCtx } from '../../src/context.ts'

export default function register(app: AppContext): void {
  const roleP = app.p('role')
  const teamP = app.p('teamField')
  void roleP
  void teamP

  app.route('userUpdate', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const patch = (ctx.body ?? {}) as Record<string, unknown>
    const columns: Record<string, string> = { name: 'name', email: 'email' }

    const sets: string[] = []
    const vals: unknown[] = []
    for (const key of Object.keys(patch)) {
      const col = columns[key]
      if (col) { sets.push(`${col} = ?`); vals.push(String(patch[key])) }
    }
    if (sets.length === 0) return ctx.json({ ok: true, updated: 0 })

    const target = String(ctx.session.get('userId') ?? '')
    vals.push(target)
    app.run(`UPDATE users SET ${sets.join(', ')} WHERE ext_id = ?`, vals)
    return ctx.json({ ok: true, updated: sets.length })
  }, { encoding: 'json' })
}
