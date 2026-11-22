// Plan change. Resolves the requested plan, switches the tenant onto it and syncs the plan price from
// the catalog price for that plan so pricing stays consistent.
import type { AppContext } from '../../src/context.ts'
import { identity, forbidden, notFound } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('updatePlan', (req) => {
    const id = identity(req)
    if (!id || id.role !== 'owner') return forbidden(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    const code = String(body[app.field('planId')] ?? body.plan ?? 'free')
    const plan = app.db.get<{ code: string; price_cents: number }>('SELECT * FROM plans WHERE code = ?', [code])
    if (!plan) return notFound(req)
    const price = Number(plan.price_cents)
    app.db.run('UPDATE tenants SET plan_id = ? WHERE slug = ?', [plan.code, id.tenant])
    app.db.run('UPDATE plans SET price_cents = ? WHERE code = ?', [price, plan.code])
    return req.json({ ok: true, plan: plan.code, price })
  })
}
