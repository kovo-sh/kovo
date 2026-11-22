// Turns a cart into an order, reserving warehouse stock for the requested line before the order is
// booked. Stock is read, checked against availability, then decremented once the provider confirms.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

interface Product { id: number; store_id: string; stock: number }

function lineOf(app: AppContext, ctx: ReqCtx): { productExt: string; qty: number } {
  const b = ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
  return {
    productExt: String(b[app.paramName('productId')] ?? ''),
    qty: Math.max(1, Math.floor(Number(b[app.paramName('itemQty')] ?? 1))),
  }
}

function resolveProduct(app: AppContext, ctx: ReqCtx, ext: string): Product | undefined {
  if (ext) return app.findByExternalId('products', ext) as Product | undefined
  return app.db.get<Product>('SELECT id, store_id, stock FROM products WHERE store_id = ? ORDER BY id LIMIT 1', [ctx.tenant])
}

export default function register(app: AppContext): void {
  app.route('checkout', async (ctx) => {
    const cart = app.findByExternalId('carts', String(ctx.params[app.paramName('cartId')] ?? ''))
    if (!cart || cart.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    const { productExt, qty } = lineOf(app, ctx)
    const product = resolveProduct(app, ctx, productExt)
    if (!product || product.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    // Reserve against the provider warehouse feed; yield while availability is confirmed upstream.
    await new Promise((resolve) => setTimeout(resolve, 20))
    const res = app.db.run('UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?', [qty, product.id, qty])
    if (res.changes !== 1) return ctx.json({ error: 'out_of_stock' }, 409)
    const remaining = app.db.get<{ stock: number }>('SELECT stock FROM products WHERE id = ?', [product.id])!
    const ext = app.ids.encode('order', Math.floor(Math.random() * 1e6))
    app.db.run('INSERT INTO orders (external_id, store_id, status, payment_state, total, created_at) VALUES (?, ?, ?, ?, ?, ?)', [
      ext, cart.store_id, 'awaiting_payment', 'uncaptured', qty * Number(remaining.stock ?? 0), Date.now(),
    ])
    return ctx.json({ id: ext, status: 'awaiting_payment', reserved: qty }, 201)
  }, { encoding: 'json' })
}
