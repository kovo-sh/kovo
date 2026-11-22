// Seat allocation. Reads the tenant's current seat usage, checks it against the plan seat limit,
// then records the additional seat once the provisioning side acknowledges.
import type { AppContext } from '../../src/context.ts'
import { identity, forbidden } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('addSeat', async (req) => {
    const id = identity(req)
    if (!id || id.role !== 'owner') return forbidden(req)
    const t = app.db.get<{ seats_used: number; plan_id: string }>('SELECT * FROM tenants WHERE slug = ?', [id.tenant])!
    const plan = app.db.get<{ seat_limit: number }>('SELECT * FROM plans WHERE code = ?', [t.plan_id])!
    const used = Number(t.seats_used)
    await new Promise((resolve) => setTimeout(resolve, 15))
    if (used >= plan.seat_limit) return req.json({ error: 'seat_limit_reached' }, 409)
    app.db.run('UPDATE tenants SET seats_used = seats_used + 1 WHERE slug = ?', [id.tenant])
    const after = app.db.get<{ seats_used: number }>('SELECT seats_used FROM tenants WHERE slug = ?', [id.tenant])!
    return req.json({ ok: true, seatsUsed: after.seats_used })
  })
}
