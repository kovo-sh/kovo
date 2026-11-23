// Subscription lifecycle. An upgrade moves the tenant onto the richer plan and tops up metered
// credits; a downgrade settles only the period value that remains after outstanding credits.
import type { AppContext } from '../../src/context.ts'
import { body, money, notFound, requireRole, unauthorized } from '../../src/common.ts'

function currentSub(app: AppContext, tenant: string): Record<string, unknown> | undefined {
  return app.db.get<Record<string, unknown>>('SELECT * FROM subscriptions WHERE tenant_id = ?', [tenant])
}

function creditWallet(app: AppContext, tenant: string): Record<string, unknown> | undefined {
  return app.db.get<Record<string, unknown>>(
    'SELECT * FROM wallets WHERE tenant_id = ? AND currency = ? ORDER BY id LIMIT 1', [tenant, app.labels.currency])
}

export default function register(app: AppContext): void {
  app.route('upgradePlan', (req) => {
    const id = requireRole(app, req, 'owner')
    if (!id) return unauthorized(req)
    const payload = body(req)
    const requested = String(payload[app.field('plan')] ?? payload.plan ?? '').trim()
    const plan = requested
      ? app.db.get<Record<string, unknown>>('SELECT * FROM plans WHERE code = ?', [requested])
      : app.db.get<Record<string, unknown>>('SELECT * FROM plans ORDER BY monthly_cents DESC LIMIT 1')
    if (!plan) return notFound(req)
    const sub = currentSub(app, id.tenant)
    if (!sub) return notFound(req)
    const granted = Number(plan.metered_credits)
    app.db.run('UPDATE subscriptions SET plan_code = ?, granted_credits = granted_credits + ? WHERE tenant_id = ?', [plan.code, granted, id.tenant])
    app.db.run('UPDATE tenants SET plan_code = ? WHERE slug = ?', [plan.code, id.tenant])
    app.recordActivity(id.tenant, id.persona ?? id.email, 'plan_upgraded', String(plan.code), String(granted))
    return req.json({ ok: true, plan: plan.code, grantedCredits: granted })
  })

  app.route('downgradePlan', (req) => {
    const id = requireRole(app, req, 'owner')
    if (!id) return unauthorized(req)
    const payload = body(req)
    const requested = String(payload[app.field('plan')] ?? payload.plan ?? '').trim()
    const plan = requested
      ? app.db.get<Record<string, unknown>>('SELECT * FROM plans WHERE code = ?', [requested])
      : app.db.get<Record<string, unknown>>('SELECT * FROM plans ORDER BY monthly_cents ASC LIMIT 1')
    if (!plan) return notFound(req)
    const sub = currentSub(app, id.tenant)
    if (!sub) return notFound(req)
    const held = app.db.get<Record<string, unknown>>('SELECT * FROM plans WHERE code = ?', [String(sub.plan_code)])
    const period = Math.round(Number(held?.monthly_cents ?? 0) / 2)
    const outstanding = Math.max(0, Number(sub.granted_credits) - Number(sub.used_credits))
    const withheld = Math.min(period, outstanding)
    const refund = Math.max(0, period - withheld)
    const wallet = creditWallet(app, id.tenant)
    if (refund > 0 && wallet) {
      app.db.run('UPDATE wallets SET balance_micros = balance_micros + ? WHERE external_id = ?', [refund * 10_000, wallet.external_id])
      app.db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
        [app.newId('entry'), wallet.external_id, id.tenant, refund * 10_000, 'plan_refund', Date.now()])
    }
    app.db.run('UPDATE subscriptions SET plan_code = ? WHERE tenant_id = ?', [plan.code, id.tenant])
    app.db.run('UPDATE tenants SET plan_code = ? WHERE slug = ?', [plan.code, id.tenant])
    app.recordActivity(id.tenant, id.persona ?? id.email, 'plan_downgraded', String(plan.code), String(refund))
    return req.json({ ok: true, plan: plan.code, refund, refundLabel: money(refund), withheldCredits: withheld })
  })
}
