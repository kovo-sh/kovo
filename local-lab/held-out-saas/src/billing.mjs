// Billing & commerce: invoices, sales-order search, checkout workflow, credit vouchers, analytics.
import { sendJson } from './http-util.mjs'
import { delay } from './http-util.mjs'
import { legacyCompat } from './db.mjs'
import { marker } from './markers.mjs'
import { fireWebhookEvent } from './webhooks.mjs'

export function register(router, ctx) {
  router.get('/api/v1/invoices', c => {
    const user = c.requireUser()
    if (!user) return
    const rows = [...ctx.s.invoices.values()].filter(i => i.tenantId === user.tenant)
    sendJson(c.res, 200, { invoices: rows })
  })

  // hos-01: BOLA — invoices are looked up by id only; the tenant of the caller is never compared.
  router.get('/api/v1/invoices/:id', c => {
    const user = c.requireUser()
    if (!user) return
    const invoice = ctx.s.invoices.get(c.params.id)
    if (!invoice) return sendJson(c.res, 404, { error: 'not_found' })
    if (ctx.fixed('hos-01') && invoice.tenantId !== user.tenant) return sendJson(c.res, 403, { error: 'forbidden' })
    sendJson(c.res, 200, invoice)
  })

  // hos-06: SQL injection (query string, boolean-visible).
  router.get('/api/v1/sales-orders', c => {
    const user = c.requireUser()
    if (!user) return
    const ref = c.query.ref
    try {
      let rows
      if (ctx.fixed('hos-06')) {
        rows = ref === undefined
          ? ctx.s.db.prepare('SELECT ref, status, total, memo FROM sales_orders WHERE tenant_id = ?').all(user.tenant)
          : ctx.s.db.prepare('SELECT ref, status, total, memo FROM sales_orders WHERE tenant_id = ? AND ref = ?').all(user.tenant, String(ref))
      } else {
        const sql = ref === undefined
          ? `SELECT ref, status, total, memo FROM sales_orders WHERE tenant_id = '${user.tenant}'`
          : `SELECT ref, status, total, memo FROM sales_orders WHERE tenant_id = '${user.tenant}' AND ref = '${ref}'`
        rows = ctx.s.db.prepare(sql).all()
      }
      sendJson(c.res, 200, { orders: rows.map(r => ({ ...r })) })
    } catch (err) {
      sendJson(c.res, 500, { error: 'query_failed', detail: String(err?.message ?? err) })
    }
  })

  // hos-08: blind, time-based SQL injection through a JSON filter. The response never changes.
  router.post('/api/v1/analytics/query', async c => {
    const user = c.requireUser()
    if (!user) return
    const body = await c.json()
    const name = String(body?.filter?.name ?? '')
    try {
      if (ctx.fixed('hos-08')) {
        ctx.s.db.prepare('SELECT COUNT(*) AS c FROM events WHERE tenant_id = ? AND name = ?').get(user.tenant, name)
      } else {
        ctx.s.db.prepare(legacyCompat(`SELECT COUNT(*) AS c FROM events WHERE tenant_id = '${user.tenant}' AND name = '${name}'`)).get()
      }
    } catch {
      // Errors are swallowed on purpose: the endpoint is blind.
    }
    sendJson(c.res, 200, { ok: true, queued: true })
  })

  // ---- checkout workflow: draft -> pay -> confirm --------------------------------------------------------
  router.post('/api/v1/checkout/orders', async c => {
    const user = c.requireUser()
    if (!user) return
    const body = await c.json()
    const sku = String(body.sku ?? '1')
    const qty = Math.max(1, Math.min(Number.parseInt(String(body.qty ?? '1'), 10) || 1, 50))
    const product = ctx.s.db.prepare('SELECT price FROM products WHERE sku = ? AND active = 1').get(sku)
    if (!product) return sendJson(c.res, 404, { error: 'unknown_sku' })
    const id = `ord_${++ctx.s.counters.order}`
    const order = { id, tenantId: user.tenant, sku, qty, total: Number(product.price) * qty, status: 'draft', paid: false }
    ctx.s.checkoutOrders.set(id, order)
    sendJson(c.res, 201, order)
  })

  const loadOrder = (c, user) => {
    const order = ctx.s.checkoutOrders.get(c.params.id)
    if (!order || order.tenantId !== user.tenant) {
      sendJson(c.res, 404, { error: 'not_found' })
      return null
    }
    return order
  }

  router.post('/api/v1/checkout/orders/:id/pay', async c => {
    const user = c.requireUser()
    if (!user) return
    const order = loadOrder(c, user)
    if (!order) return
    const body = await c.json()
    if (!body.paymentToken) return sendJson(c.res, 402, { error: 'payment_token_required' })
    order.paid = true
    order.status = 'paid'
    sendJson(c.res, 200, order)
  })

  // hos-13: workflow step-skip — confirmation never verifies that the payment step happened.
  router.post('/api/v1/checkout/orders/:id/confirm', async c => {
    const user = c.requireUser()
    if (!user) return
    const order = loadOrder(c, user)
    if (!order) return
    if (ctx.fixed('hos-13') && order.status !== 'paid') {
      return sendJson(c.res, 409, { error: 'payment_required', status: order.status })
    }
    order.status = 'confirmed'
    order.licenseKey = marker('hos-13')
    fireWebhookEvent(ctx, user.tenant, 'order.confirmed', { id: order.id }).catch(() => undefined)
    sendJson(c.res, 200, order)
  })

  // ---- credit vouchers: single-use, redeemable once per voucher ------------------------------------------
  router.get('/api/v1/credits', c => {
    const user = c.requireUser()
    if (!user) return
    sendJson(c.res, 200, { tenant: user.tenant, balance: ctx.s.credits.get(user.tenant) ?? 0 })
  })

  router.post('/api/v1/credits/vouchers', c => {
    const user = c.requireUser()
    if (!user) return
    const code = `VCH-${Math.random().toString(16).slice(2, 10).toUpperCase()}`
    ctx.s.vouchers.set(code, { code, tenantId: user.tenant, value: 25, redeemed: false, redemptions: 0 })
    sendJson(c.res, 201, { code, value: 25 })
  })

  // hos-14: check-then-act race — the "already redeemed" flag is set only after an async fraud check.
  router.post('/api/v1/credits/redeem', async c => {
    const user = c.requireUser()
    if (!user) return
    const body = await c.json()
    const voucher = ctx.s.vouchers.get(String(body.code ?? ''))
    if (!voucher || voucher.tenantId !== user.tenant) return sendJson(c.res, 404, { error: 'unknown_voucher' })
    if (voucher.redeemed) return sendJson(c.res, 409, { error: 'already_redeemed' })
    if (ctx.fixed('hos-14')) voucher.redeemed = true
    await delay(15) // simulated fraud-screening call
    ctx.s.credits.set(user.tenant, (ctx.s.credits.get(user.tenant) ?? 0) + voucher.value)
    voucher.redeemed = true
    voucher.redemptions += 1
    const out = { redeemed: true, credited: voucher.value, balance: ctx.s.credits.get(user.tenant) }
    if (voucher.redemptions > 1) out.anomalyRef = marker('hos-14')
    sendJson(c.res, 200, out)
  })
}
