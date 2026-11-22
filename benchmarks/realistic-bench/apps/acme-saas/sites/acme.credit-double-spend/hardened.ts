// Credit application. Deducts the amount with a single conditional update that only succeeds while
// the balance still covers it, once settlement acknowledges.
import type { AppContext } from '../../src/context.ts'
import { identity, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('applyCredit', async (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    const amount = Math.abs(Number((req.body as Record<string, unknown>)?.[app.field('amount')] ?? 0))
    if (amount <= 0) return req.json({ error: 'insufficient_credits' }, 409)
    await new Promise((resolve) => setTimeout(resolve, 15))
    const r = app.db.run('UPDATE tenants SET credits = credits - ? WHERE slug = ? AND credits >= ?', [amount, id.tenant, amount])
    if (r.changes === 0) return req.json({ error: 'insufficient_credits' }, 409)
    const after = app.db.get<{ credits: number }>('SELECT credits FROM tenants WHERE slug = ?', [id.tenant])!
    app.db.run('INSERT INTO credit_ledger (tenant_id,delta,balance) VALUES (?,?,?)', [id.tenant, -amount, after.credits])
    return req.json({ ok: true, balance: after.credits })
  })
}
