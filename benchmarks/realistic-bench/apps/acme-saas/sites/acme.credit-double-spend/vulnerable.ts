// Credit application. Reads the tenant's current credit balance, does the availability math, then
// writes the deduction once settlement acknowledges.
import type { AppContext } from '../../src/context.ts'
import { identity, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('applyCredit', async (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    const amount = Math.abs(Number((req.body as Record<string, unknown>)?.[app.field('amount')] ?? 0))
    const t = app.db.get<{ credits: number }>('SELECT credits FROM tenants WHERE slug = ?', [id.tenant])!
    const balance = Number(t.credits)
    await new Promise((resolve) => setTimeout(resolve, 15))
    if (amount <= 0 || amount > balance) return req.json({ error: 'insufficient_credits', balance }, 409)
    app.db.run('UPDATE tenants SET credits = credits - ? WHERE slug = ?', [amount, id.tenant])
    const after = app.db.get<{ credits: number }>('SELECT credits FROM tenants WHERE slug = ?', [id.tenant])!
    app.db.run('INSERT INTO credit_ledger (tenant_id,delta,balance) VALUES (?,?,?)', [id.tenant, -amount, after.credits])
    return req.json({ ok: true, balance: after.credits })
  })
}
