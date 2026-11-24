// Storefront product page. Renders a store's product with a short-lived cache so repeat views are
// cheap, and personalizes the page with the signed-in viewer's loyalty note. The note is only
// resolved for the authenticated viewer's own store: an anonymous or foreign-store caller gets the
// store's public display name, so a public read never carries another tenant's customer canary.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

function renderStorePage(app: AppContext, ctx: ReqCtx): Record<string, unknown> {
  const storeId = String(ctx.params[app.paramName('storeId')] ?? '')
  const productId = String(ctx.params[app.paramName('productId')] ?? '')
  const product = app.findByExternalId('products', productId)
  const viewer = String(ctx.headers['x-store'] ?? ctx.tenant ?? storeId)
  const shop = app.db.get<{ name: string }>('SELECT name FROM stores WHERE slug = ? LIMIT 1', [viewer])
  // Customer-scoped personalization is only for the signed-in store itself. A public/anonymous read
  // (or a forged x-store header) gets the store's public name instead of the loyalty note canary.
  const member = ctx.tenant !== null && ctx.tenant === viewer
    ? app.db.get<{ note: string }>('SELECT note FROM customers WHERE store_id = ? LIMIT 1', [viewer])
    : undefined
  return {
    store: storeId,
    viewer,
    product: product ? { id: product.external_id, title: product.title, price: product.price } : null,
    memberNote: member ? String(member.note) : shop ? `Welcome to ${String(shop.name)}` : '',
  }
}

export default function register(app: AppContext): void {
  app.route('storeProductPage', (ctx: ReqCtx) => ctx.json(renderStorePage(app, ctx)), {
    cache: { ttlMs: 30_000 },
  })
}
