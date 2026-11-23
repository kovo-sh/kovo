// Billing area: invoices (CRUD + preview + PDF export), orders, payment intents and subscription plan
// changes. Unmounted site routes for refund/line-item math and payment-intent binding get safe default
// implementations here; a mounted site module owns its route key instead.
import type { AppContext, OrderRow } from '../context.ts'
import { body, invoiceView, money, notFound, orderView, param, requireRole, requireSession, unauthorized } from '../common.ts'

interface Line { sku: string; name: string; unit: number; qty: number }

function lines(value: unknown): Line[] {
  if (!Array.isArray(value)) return []
  return value.map((raw) => {
    const r = (raw ?? {}) as Record<string, unknown>
    return {
      sku: String(r.sku ?? 'SKU-ITEM'),
      name: String(r.name ?? 'Item'),
      unit: Math.max(0, Math.round(Number(r.unit ?? r.unit_cents ?? 0))),
      qty: Math.max(1, Math.round(Number(r.qty ?? 1))),
    }
  })
}

function subtotalOf(items: Line[]): number {
  return items.reduce((sum, i) => sum + i.unit * i.qty, 0)
}

function writeLines(ctx: AppContext, orderExt: string, tenant: string, items: Line[], discount: number): void {
  ctx.db.run('DELETE FROM order_items WHERE order_id = ? AND tenant_id = ?', [orderExt, tenant])
  const total = subtotalOf(items)
  let allocated = 0
  items.forEach((item, index) => {
    const share = total > 0 ? (index === items.length - 1 ? discount - allocated : Math.round((discount * item.unit * item.qty) / total)) : 0
    allocated += share
    ctx.db.run('INSERT INTO order_items (external_id,order_id,tenant_id,sku,name,unit_cents,qty,discount_cents) VALUES (?,?,?,?,?,?,?,?)',
      [ctx.newId('line'), orderExt, tenant, item.sku, item.name, item.unit, item.qty, share])
  })
}

export function registerBillingRoutes(ctx: AppContext): void {
  ctx.route('listInvoices', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM invoices WHERE tenant_id = ? ORDER BY id DESC LIMIT 200', [id.tenant])
    return req.json({ items: rows.map((r) => invoiceView(ctx, r)) })
  })

  ctx.route('getInvoice', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const row = ctx.db.get<Record<string, unknown>>(
      'SELECT * FROM invoices WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'invoiceId'), id.tenant])
    if (!row) return notFound(req)
    return req.json(invoiceView(ctx, row))
  })

  ctx.route('createInvoice', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const b = body(req)
    const ext = ctx.newId('invoice')
    ctx.db.run('INSERT INTO invoices (external_id,tenant_id,number,amount_cents,status,description,note,created_at) VALUES (?,?,?,?,?,?,?,?)',
      [ext, id.tenant, String(b.number ?? `INV-${ext}`), Math.round(Number(b.amount ?? 0)), 'draft',
        String(b.description ?? ''), String(b.note ?? ''), Date.now()])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'invoice_created', ext)
    return req.json({ id: ext }, 201)
  })

  ctx.route('updateInvoice', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const row = ctx.db.get<Record<string, unknown>>(
      'SELECT * FROM invoices WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'invoiceId'), id.tenant])
    if (!row) return notFound(req)
    const b = body(req)
    ctx.db.run('UPDATE invoices SET amount_cents = ?, description = ?, note = ?, status = ? WHERE external_id = ? AND tenant_id = ?',
      [Math.round(Number(b.amount ?? row.amount_cents)), String(b.description ?? row.description),
        String(b.note ?? row.note ?? ''), String(b.status ?? row.status), row.external_id, id.tenant])
    return req.json({ ok: true })
  })

  ctx.route('deleteInvoice', (req) => {
    const id = requireRole(ctx, req, 'admin')
    if (!id) return unauthorized(req)
    ctx.db.run('DELETE FROM invoices WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'invoiceId'), id.tenant])
    return req.json({ ok: true })
  })

  ctx.route('previewInvoice', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const row = ctx.db.get<Record<string, unknown>>(
      'SELECT * FROM invoices WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'invoiceId'), id.tenant])
    if (!row) return notFound(req)
    return req.html(ctx.template.render('<article><h1>{{ number }}</h1><p>{{ description }}</p><footer>{{ note }}</footer></article>', {
      number: row.number, description: row.description, note: row.note ?? '',
    }))
  })

  // Safe default for the PDF export entry: the footer note is escaped and the artifact stays in the
  // caller tenant's export jail. A mounted site may own this route key.
  ctx.route('exportInvoicePdf', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const row = ctx.db.get<Record<string, unknown>>(
      'SELECT * FROM invoices WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'invoiceId'), id.tenant])
    if (!row) return notFound(req)
    const html = ctx.template.render('<html><body><h1>{{ number }}</h1><p>{{ description }}</p><footer>{{ note }}</footer></body></html>', {
      number: row.number, description: row.description, note: row.note ?? '',
    }, { inputDerived: true })
    const path = `/exports/${id.tenant}/invoice-${row.external_id}.html`
    ctx.vfs.write(path, html)
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'invoice_pdf', String(row.external_id))
    return req.json({ ok: true, path, bytes: html.length })
  })

  ctx.route('listOrders', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const rows = ctx.db.all<OrderRow>('SELECT * FROM orders WHERE tenant_id = ? ORDER BY id DESC LIMIT 200', [id.tenant])
    return req.json({ items: rows.map((r) => orderView(ctx, r as unknown as Record<string, unknown>)) })
  })

  ctx.route('getOrder', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const row = ctx.db.get<OrderRow>('SELECT * FROM orders WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'orderId'), id.tenant])
    if (!row) return notFound(req)
    return req.json(orderView(ctx, row as unknown as Record<string, unknown>))
  })

  // Safe default: editing a draft re-binds any open payment intent to the new total.
  ctx.route('updateOrder', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const row = ctx.db.get<OrderRow>('SELECT * FROM orders WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'orderId'), id.tenant])
    if (!row) return notFound(req)
    if (row.status !== 'draft') return req.json({ error: 'not_editable' }, 409)
    const b = body(req)
    const items = lines(b.items)
    if (items.length === 0) return req.json({ error: 'items_required' }, 400)
    const subtotal = subtotalOf(items)
    const discount = Math.round(Number(b.discount ?? row.discount_cents))
    const total = Math.max(0, subtotal - discount)
    writeLines(ctx, row.external_id, id.tenant, items, discount)
    ctx.db.run('UPDATE orders SET subtotal_cents = ?, discount_cents = ?, total_cents = ? WHERE external_id = ? AND tenant_id = ?',
      [subtotal, discount, total, row.external_id, id.tenant])
    ctx.db.run("UPDATE payment_intents SET amount_cents = ? WHERE order_id = ? AND tenant_id = ? AND status = 'requires_capture'",
      [total, row.external_id, id.tenant])
    return req.json({ ok: true, total, amountLabel: money(total) })
  })

  // Safe default for line-item refunds: credit at most the post-discount line value, never more than
  // the order's paid amount. A mounted site may own this route key.
  ctx.route('refundOrderItem', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const order = ctx.db.get<OrderRow>('SELECT * FROM orders WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'orderId'), id.tenant])
    if (!order) return notFound(req)
    const itemId = param(req, ctx, 'itemId')
    const item = ctx.db.get<Record<string, unknown>>(
      'SELECT * FROM order_items WHERE external_id = ? AND order_id = ? AND tenant_id = ?', [itemId, order.external_id, id.tenant])
    if (!item) return notFound(req)
    const net = Math.max(0, Number(item.unit_cents) * Number(item.qty) - Number(item.discount_cents))
    const already = ctx.db.get<{ total: number }>('SELECT COALESCE(SUM(amount_cents),0) AS total FROM refunds WHERE order_id = ?', [order.external_id])?.total ?? 0
    const room = Math.max(0, Number(order.paid_cents) - already)
    const amount = Math.min(net, room)
    if (amount <= 0) return req.json({ error: 'nothing_refundable' }, 409)
    const ext = ctx.newId('refund')
    ctx.db.run('INSERT INTO refunds (external_id,tenant_id,order_id,order_item_id,amount_cents,status,created_at) VALUES (?,?,?,?,?,?,?)',
      [ext, id.tenant, order.external_id, itemId, amount, 'settled', Date.now()])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'refund_issued', ext)
    return req.json({ ok: true, id: ext, amount, amountLabel: money(amount) })
  })

  ctx.route('createPaymentIntent', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const order = ctx.db.get<OrderRow>('SELECT * FROM orders WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'orderId'), id.tenant])
    if (!order) return notFound(req)
    const ext = ctx.newId('intent')
    ctx.db.run('INSERT INTO payment_intents (external_id,tenant_id,user_ext_id,order_id,amount_cents,currency,status,created_at) VALUES (?,?,?,?,?,?,?,?)',
      [ext, id.tenant, id.userExtId, order.external_id, order.total_cents, order.currency, 'requires_capture', Date.now()])
    return req.json({ id: ext, amount: order.total_cents }, 201)
  })

  ctx.route('getPaymentIntent', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const row = ctx.db.get<Record<string, unknown>>(
      'SELECT * FROM payment_intents WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'intentId'), id.tenant])
    if (!row) return notFound(req)
    return req.json({ id: row.external_id, order: row.order_id, amount: row.amount_cents, status: row.status })
  })

  // Safe default: capture requires the intent total to equal the order's current total.
  ctx.route('capturePaymentIntent', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const intent = ctx.db.get<Record<string, unknown>>(
      'SELECT * FROM payment_intents WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'intentId'), id.tenant])
    if (!intent) return notFound(req)
    const order = ctx.db.get<OrderRow>('SELECT * FROM orders WHERE external_id = ? AND tenant_id = ?', [String(intent.order_id), id.tenant])
    if (!order) return notFound(req)
    if (intent.status !== 'requires_capture') return req.json({ error: 'intent_not_capturable' }, 409)
    if (Number(intent.amount_cents) !== Number(order.total_cents)) return req.json({ error: 'amount_mismatch' }, 409)
    ctx.db.run("UPDATE payment_intents SET status = 'captured', captured_at = ? WHERE external_id = ?", [Date.now(), intent.external_id])
    ctx.db.run("UPDATE orders SET status = 'paid', paid_cents = total_cents, paid_at = ? WHERE external_id = ? AND tenant_id = ?",
      [Date.now(), order.external_id, id.tenant])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'payment_captured', order.external_id)
    return req.json({ ok: true, order: order.external_id, paid: order.total_cents })
  })

  ctx.route('upgradePlan', (req) => {
    const id = requireRole(ctx, req, 'owner')
    if (!id) return unauthorized(req)
    const code = String(body(req).plan ?? 'growth')
    const plan = ctx.db.get<Record<string, unknown>>('SELECT * FROM plans WHERE code = ?', [code])
    if (!plan) return notFound(req)
    const sub = ctx.db.get<Record<string, unknown>>('SELECT * FROM subscriptions WHERE tenant_id = ?', [id.tenant])
    if (!sub) return notFound(req)
    const granted = Number(plan.metered_credits)
    ctx.db.run('UPDATE subscriptions SET plan_code = ?, granted_credits = granted_credits + ? WHERE tenant_id = ?', [code, granted, id.tenant])
    ctx.db.run('UPDATE tenants SET plan_code = ? WHERE slug = ?', [code, id.tenant])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'plan_upgraded', String(code), String(granted))
    return req.json({ ok: true, plan: code, grantedCredits: granted })
  })

  ctx.route('downgradePlan', (req) => {
    const id = requireRole(ctx, req, 'owner')
    if (!id) return unauthorized(req)
    const code = String(body(req).plan ?? 'starter')
    const plan = ctx.db.get<Record<string, unknown>>('SELECT * FROM plans WHERE code = ?', [code])
    if (!plan) return notFound(req)
    const sub = ctx.db.get<Record<string, unknown>>('SELECT * FROM subscriptions WHERE tenant_id = ?', [id.tenant])
    if (!sub) return notFound(req)
    const price = Number(plan.monthly_cents)
    const used = Number(sub.used_credits)
    const creditValue = Math.min(price, used) // unused credit value is withheld before any cash refund
    const refund = Math.max(0, Math.round(price / 2) - creditValue)
    if (refund > 0) {
      const wallet = ctx.db.get<Record<string, unknown>>('SELECT * FROM wallets WHERE tenant_id = ? AND currency = ? ORDER BY id LIMIT 1', [id.tenant, ctx.labels.currency])
      if (wallet) {
        ctx.db.run('UPDATE wallets SET balance_micros = balance_micros + ? WHERE external_id = ?', [refund * 10_000, wallet.external_id])
        ctx.db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
          [ctx.newId('entry'), wallet.external_id, id.tenant, refund * 10_000, 'plan_refund', Date.now()])
      }
    }
    ctx.db.run('UPDATE subscriptions SET plan_code = ? WHERE tenant_id = ?', [code, id.tenant])
    ctx.db.run('UPDATE tenants SET plan_code = ? WHERE slug = ?', [code, id.tenant])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'plan_downgraded', String(code), String(refund))
    return req.json({ ok: true, plan: code, refund, refundLabel: money(refund), withheldCredits: used })
  })

  ctx.route('listCoupons', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM coupons WHERE tenant_id = ? AND active = 1 ORDER BY code', [id.tenant])
    return req.json({ items: rows.map((c) => ({ code: c.code, percent: c.percent_off, minSpend: c.min_spend_cents })) })
  })
}
