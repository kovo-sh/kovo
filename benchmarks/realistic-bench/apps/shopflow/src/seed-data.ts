// Deterministic fixtures keyed off the plan's canary salt. Two merchant tenants (A, B) plus a
// background tenant (C) with products, carts/orders, payments, gift cards, coupons, reviews, API
// tokens and provider secrets. Tenant data carries rbc_ canaries; secrets are rbs_ canaries.
import type { Db } from '../../../lib/db.ts'
import type { IdCodec } from '../../../lib/ids.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import type { Vfs } from '../../../lib/vfs.ts'
import type { VariantPlan } from '../../../lib/types.ts'

export interface SeedCtx {
  db: Db
  ids: IdCodec
  canaries: CanaryRegistry
  vfs: Vfs
  plan: VariantPlan
}

interface StorePlan { slug: string; name: string }

export function seedData(ctx: SeedCtx): void {
  const { db, ids, canaries, vfs } = ctx
  const a = ctx.plan.personas.persona_a.tenant
  const b = ctx.plan.personas.persona_b.tenant
  const stores: StorePlan[] = [
    { slug: a, name: 'Aurora Goods' },
    { slug: b, name: 'Borealis Supply' },
    { slug: 'bgshop', name: 'Cinder Market' },
  ]
  let orderN = 100
  let prodN = 200
  let cardN = 300
  let custN = 400
  let payN = 500
  let invN = 600
  let revN = 700
  let tokN = 800
  let shipN = 900

  for (const store of stores) {
    db.run('INSERT INTO stores (slug, name) VALUES (?, ?)', [store.slug, store.name])
    db.run('INSERT INTO store_config (store_id, webhook_secret, provider_key, settings_json) VALUES (?, ?, ?, ?)', [
      store.slug,
      canaries.secretToken(store.slug, 'webhook'),
      canaries.secretToken(store.slug, 'provider'),
      JSON.stringify({ currency: 'USD', timezone: 'UTC' }),
    ])
    db.run('INSERT INTO api_tokens (external_id, store_id, label, token, scope) VALUES (?, ?, ?, ?, ?)', [
      ids.encode('token', ++tokN), store.slug, 'server-key', canaries.secretToken(store.slug, 'apitoken'), 'read_write',
    ])

    const custId = ++custN
    db.run('INSERT INTO customers (external_id, store_id, name, email, note) VALUES (?, ?, ?, ?, ?)', [
      ids.encode('customer', custId), store.slug, 'Dana Rivera', `dana@${store.slug}.test`,
      `loyalty ${canaries.tenantToken(store.slug, 'customer')}`,
    ])

    const products: number[] = []
    for (let i = 0; i < 3; i++) {
      const pid = ++prodN
      db.run('INSERT INTO products (external_id, store_id, title, price, stock, body_html) VALUES (?, ?, ?, ?, ?, ?)', [
        ids.encode('product', pid), store.slug, `Item ${i + 1}`, 1200 + i * 500, 5, `<p>Quality item ${i + 1}</p>`,
      ])
      products.push(Number(db.get<{ id: number }>('SELECT last_insert_rowid() AS id')!.id))
    }

    // A fulfilled + paid order, and an order still awaiting payment capture.
    const paidId = ++orderN
    db.run('INSERT INTO orders (external_id, store_id, customer_id, status, payment_state, total, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)', [
      ids.encode('order', paidId), store.slug, custId, 'confirmed', 'captured', 3400, 1_700_000_000,
    ])
    const paidRow = db.get<{ id: number }>('SELECT last_insert_rowid() AS id')!.id
    db.run('INSERT INTO payments (external_id, store_id, order_id, amount, status, captured) VALUES (?, ?, ?, ?, ?, ?)', [
      ids.encode('payment', ++payN), store.slug, paidRow, 3400, 'captured', 1,
    ])

    const pendingId = ++orderN
    db.run('INSERT INTO orders (external_id, store_id, customer_id, status, payment_state, total, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)', [
      ids.encode('order', pendingId), store.slug, custId, 'awaiting_payment', 'uncaptured', 2000, 1_700_000_100,
    ])

    const cardId = ++cardN
    db.run('INSERT INTO gift_cards (external_id, store_id, code, balance, initial) VALUES (?, ?, ?, ?, ?)', [
      ids.encode('giftcard', cardId), store.slug, `GC-${store.slug}-${cardId}`, 5000, 5000,
    ])

    db.run('INSERT INTO coupons (store_id, code, kind, value, single_use) VALUES (?, ?, ?, ?, ?)', [
      store.slug, 'WELCOME10', 'percent', 10, 1,
    ])

    const revId = ++revN
    db.run('INSERT INTO reviews (external_id, store_id, product_id, author, body, approved) VALUES (?, ?, ?, ?, ?, ?)', [
      ids.encode('review', revId), store.slug, products[0]!, 'Jess', '<p>Loved it</p>', 1,
    ])

    const invId = ++invN
    const invPath = `/exports/${store.slug}/invoice-${ids.encode('order', paidId)}.pdf`
    vfs.write(invPath, `%PDF-1.4\n% invoice for order ${ids.encode('order', paidId)} total 3400\n`)
    db.run('INSERT INTO invoices (external_id, store_id, order_id, path) VALUES (?, ?, ?, ?)', [
      ids.encode('invoice', invId), store.slug, paidRow, invPath,
    ])

    const shipId = ++shipN
    db.run('INSERT INTO shipments (external_id, store_id, order_id, status, label_url) VALUES (?, ?, ?, ?, ?)', [
      ids.encode('shipment', shipId), store.slug, paidRow, 'pending', `/labels/${store.slug}/${ids.encode('shipment', shipId)}.pdf`,
    ])
  }
}
