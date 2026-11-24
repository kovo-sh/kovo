// Storefront surfaces: catalog browse/search, product reviews, carts and gift-card lookups.
import type { AppContext } from './context.ts'
import type { ReqCtx } from '../../../lib/http.ts'

function body(ctx: ReqCtx): Record<string, unknown> {
  return ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
}

export default function register(app: AppContext): void {
  const db = app.db
  const storeFor = (ctx: ReqCtx): string => ctx.tenant ?? app.plan.personas.persona_a.tenant

  app.route('listProducts', (ctx) => {
    const rows = db.all('SELECT external_id, title, price, stock FROM products WHERE store_id = ?', [storeFor(ctx)])
    return ctx.json({ products: rows })
  })

  app.route('getProduct', (ctx) => {
    const row = app.findByExternalId('products', String(ctx.params[app.paramName('productId')] ?? ''))
    return row ? ctx.json(row) : ctx.json({ error: 'not_found' }, 404)
  })

  app.route('searchProducts', (ctx) => {
    const q = String(ctx.query[app.paramName('searchQuery')] ?? '')
    // Parameterized lookup: the search term never reaches the SQL structure.
    const rows = db.all('SELECT external_id, title, price FROM products WHERE store_id = ? AND title LIKE ?', [storeFor(ctx), `%${q}%`])
    return ctx.json({ query: q, results: rows })
  })

  app.route('productReviews', (ctx) => {
    const prod = app.findByExternalId('products', String(ctx.params[app.paramName('productId')] ?? ''))
    if (!prod) return ctx.json({ error: 'not_found' }, 404)
    const rows = db.all('SELECT external_id, author, body, approved FROM reviews WHERE product_id = ? AND approved = 1', [prod.id])
    return ctx.json({ reviews: rows })
  })

  app.route('submitReview', (ctx) => {
    const prod = app.findByExternalId('products', String(ctx.params[app.paramName('productId')] ?? ''))
    if (!prod) return ctx.json({ error: 'not_found' }, 404)
    const text = String(body(ctx).body ?? '')
    const clean = text.replace(/[<>]/g, '')
    const ext = app.ids.encode('review', Math.floor(Math.random() * 1e6))
    db.run('INSERT INTO reviews (external_id, store_id, product_id, author, body, approved) VALUES (?, ?, ?, ?, ?, 0)', [
      ext, prod.store_id, prod.id, String(body(ctx).author ?? 'guest'), clean,
    ])
    return ctx.json({ id: ext, status: 'pending_moderation' }, 201)
  })

  app.route('listReviews', (ctx) => {
    const rows = db.all('SELECT external_id, product_id, author, approved FROM reviews WHERE store_id = ?', [storeFor(ctx)])
    return ctx.json({ reviews: rows })
  })

  app.route('getReview', (ctx) => {
    const row = app.findByExternalId('reviews', String(ctx.params[app.paramName('reviewId')] ?? ''))
    return row ? ctx.json(row) : ctx.json({ error: 'not_found' }, 404)
  })

  app.route('createCart', (ctx) => {
    const ext = app.ids.encode('cart', Math.floor(Math.random() * 1e6))
    db.run('INSERT INTO carts (external_id, store_id, owner, status) VALUES (?, ?, ?, ?)', [ext, storeFor(ctx), ctx.actor, 'open'])
    return ctx.json({ id: ext, status: 'open' }, 201)
  })

  // Carts are owner-scoped: an id is not an authorization token. Guest carts remain readable by
  // the anonymous actor that created them; another persona or a different tenant gets the same 404
  // as an unknown id, which is what the checkout/race targets already assume.
  const ownsCart = (ctx: ReqCtx, cart: { owner?: unknown }): boolean => cart.owner === ctx.actor

  app.route('getCart', (ctx) => {
    const cart = app.findByExternalId('carts', String(ctx.params[app.paramName('cartId')] ?? ''))
    if (!cart || !ownsCart(ctx, cart)) return ctx.json({ error: 'not_found' }, 404)
    const items = db.all('SELECT product_id, qty, unit_price FROM cart_items WHERE cart_id = ?', [cart.id])
    return ctx.json({ cart, items })
  })

  app.route('addCartItem', (ctx) => {
    const cart = app.findByExternalId('carts', String(ctx.params[app.paramName('cartId')] ?? ''))
    if (!cart || !ownsCart(ctx, cart)) return ctx.json({ error: 'not_found' }, 404)
    const qty = Number(body(ctx)[app.paramName('itemQty')] ?? 1)
    if (!Number.isFinite(qty) || qty < 1) return ctx.json({ error: 'invalid_quantity' }, 400)
    db.run('INSERT INTO cart_items (cart_id, product_id, qty, unit_price) VALUES (?, ?, ?, ?)', [cart.id, 0, Math.floor(qty), 1200])
    return ctx.json({ ok: true }, 201)
  })

  app.route('listGiftCards', (ctx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    const rows = db.all('SELECT external_id, code, balance FROM gift_cards WHERE store_id = ?', [ctx.tenant])
    return ctx.json({ giftCards: rows })
  })

  app.route('getGiftCard', (ctx) => {
    const row = app.findByExternalId('gift_cards', String(ctx.params[app.paramName('giftCardId')] ?? ''))
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    return ctx.json(row)
  })
}
