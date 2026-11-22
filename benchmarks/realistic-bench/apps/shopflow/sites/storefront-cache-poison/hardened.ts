// Storefront product page. Renders a store's product with a short-lived cache so repeat views are
// cheap, and labels the page with the viewer's store name; no per-viewer account data is placed in the
// cacheable body.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

function renderStorePage(app: AppContext, ctx: ReqCtx): Record<string, unknown> {
  const storeId = String(ctx.params[app.paramName('storeId')] ?? '')
  const productId = String(ctx.params[app.paramName('productId')] ?? '')
  const product = app.findByExternalId('products', productId)
  const viewer = String(ctx.headers['x-store'] ?? ctx.tenant ?? storeId)
  const shop = app.db.get<{ name: string }>('SELECT name FROM stores WHERE slug = ? LIMIT 1', [viewer])
  return {
    store: storeId,
    viewer,
    product: product ? { id: product.external_id, title: product.title, price: product.price } : null,
    memberNote: shop ? `Welcome to ${String(shop.name)}` : '',
  }
}

export default function register(app: AppContext): void {
  app.route('storeProductPage', (ctx: ReqCtx) => ctx.json(renderStorePage(app, ctx)), {
    cache: { ttlMs: 30_000 },
  })
}
