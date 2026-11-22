// Seat allocation. Records the additional seat with a single conditional update that only succeeds
// while the tenant is still under its plan seat limit, once the provisioning side acknowledges.
import type { AppContext } from '../../src/context.ts'
import { identity, forbidden } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('addSeat', async (req) => {
    const id = identity(req)
    if (!id || id.role !== 'owner') return forbidden(req)
    const t = app.db.get<{ seats_used: number; plan_id: string }>('SELECT * FROM tenants WHERE slug = ?', [id.tenant])!
    const plan = app.db.get<{ seat_limit: number }>('SELECT * FROM plans WHERE code = ?', [t.plan_id])!
    await new Promise((resolve) => setTimeout(resolve, 15))
    const r = app.db.run('UPDATE tenants SET seats_used = seats_used + 1 WHERE slug = ? AND seats_used < ?',
      [id.tenant, plan.seat_limit])
    if (r.changes === 0) return req.json({ error: 'seat_limit_reached' }, 409)
    const after = app.db.get<{ seats_used: number }>('SELECT seats_used FROM tenants WHERE slug = ?', [id.tenant])!
    return req.json({ ok: true, seatsUsed: after.seats_used })
  })
}
