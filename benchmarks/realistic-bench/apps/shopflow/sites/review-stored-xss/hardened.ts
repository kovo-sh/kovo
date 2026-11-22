// Product reviews. Shoppers submit reviews (all markup is stripped to plain text), and staff see
// pending reviews in the moderation queue with each field HTML-escaped before it is rendered.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

function body(ctx: ReqCtx): Record<string, unknown> {
  return ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
}
function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

export default function register(app: AppContext): void {
  const db = app.db

  app.route('submitReview', (ctx: ReqCtx) => {
    const prod = app.findByExternalId('products', String(ctx.params[app.paramName('productId')] ?? ''))
    if (!prod) return ctx.json({ error: 'not_found' }, 404)
    const text = String(body(ctx).body ?? '')
    const clean = text.replace(/<[^>]*>/g, '')
    const ext = app.ids.encode('review', Math.floor(Math.random() * 1e6))
    db.run('INSERT INTO reviews (external_id, store_id, product_id, author, body, approved) VALUES (?, ?, ?, ?, ?, 0)', [
      ext, prod.store_id, prod.id, String(body(ctx).author ?? 'guest'), clean,
    ])
    return ctx.json({ id: ext, status: 'pending_moderation' }, 201)
  })

  app.route('moderationQueue', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    const rows = db.all<{ external_id: string; author: string; body: string }>(
      'SELECT external_id, author, body FROM reviews WHERE store_id = ? AND approved = 0', [ctx.tenant])
    const items = rows
      .map((r) => `<li data-id="${escapeHtml(r.external_id)}"><strong>${escapeHtml(r.author)}</strong><div>${escapeHtml(r.body)}</div></li>`)
      .join('')
    return ctx.html(`<ul class="queue">${items}</ul>`)
  })
}
