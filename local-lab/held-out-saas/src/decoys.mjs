// Six hard decoys: endpoints that LOOK like the planted classes but are correctly hardened.
// A scanner that "confirms" any of these is producing a false positive.
import { escapeHtml, sendHtml, sendJson, sendText } from './http-util.mjs'
import { tokenFromRequest, verifyStrict } from './auth.mjs'
import { xmlImportHandler } from './xml-import.mjs'

const PUBLIC_PLANS = [
  { sku: '1', name: 'Starter plan', price: 19 },
  { sku: '2', name: 'Team plan', price: 99 },
  { sku: '3', name: 'Enterprise plan', price: 499 },
]

export function register(router, ctx) {
  // hos-d1: SQLi look-alike — fully parameterised catalog search (quotes/comments are inert data).
  router.get('/api/v1/catalog/search', c => {
    const user = c.requireUser()
    if (!user) return
    const q = String(c.query.q ?? '')
    const rows = ctx.s.db
      .prepare('SELECT id, sku, name, price FROM products WHERE active = 1 AND (sku = ? OR name LIKE ?)')
      .all(q, `%${q.replace(/[%_]/g, '')}%`)
    sendJson(c.res, 200, { results: rows.map(r => ({ ...r })), count: rows.length })
  })

  // hos-d2: BOLA look-alike — v2 invoices enforce tenant ownership and answer 403 cross-tenant.
  router.get('/api/v2/invoices/:id', c => {
    const user = c.requireUser()
    if (!user) return
    const invoice = ctx.s.invoices.get(c.params.id)
    if (!invoice) return sendJson(c.res, 404, { error: 'not_found' })
    if (invoice.tenantId !== user.tenant) return sendJson(c.res, 403, { error: 'forbidden' })
    sendJson(c.res, 200, invoice)
  })

  // hos-d3: stored-XSS look-alike — notes are stored raw but always HTML-escaped on output.
  router.post('/api/v1/notes', async c => {
    const user = c.requireUser()
    if (!user) return
    const body = await c.json()
    const project = ctx.s.projects.get(String(body.projectId ?? ''))
    if (!project || project.tenantId !== user.tenant) return sendJson(c.res, 404, { error: 'project_not_found' })
    const note = { id: `n_${++ctx.s.counters.note}`, projectId: project.id, author: user.userId, body: String(body.body ?? '').slice(0, 2000) }
    ctx.s.notes.push(note)
    sendJson(c.res, 201, { id: note.id })
  })

  router.get('/app/projects/:id/notes', c => {
    const user = c.requireUser()
    if (!user) return
    const project = ctx.s.projects.get(c.params.id)
    if (!project || project.tenantId !== user.tenant) return sendJson(c.res, 404, { error: 'project_not_found' })
    const items = ctx.s.notes
      .filter(n => n.projectId === project.id)
      .map(n => `<li class="note">${escapeHtml(n.body)}</li>`)
      .join('')
    sendHtml(c.res, 200, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Notes</title></head><body><h1>Notes - ${escapeHtml(project.name)}</h1><ul id="notes">${items}</ul></body></html>`)
  })

  // hos-d4: JWT look-alike — strict HS256 verifier (rejects alg none, stripped/tampered signatures, jku/kid tricks).
  router.get('/api/v2/session', c => {
    const claims = verifyStrict(tokenFromRequest(c.req))
    if (!claims) return sendJson(c.res, 401, { error: 'invalid_token' }, { 'www-authenticate': 'Bearer realm="orbit"' })
    sendJson(c.res, 200, { session: 'v2', sub: claims.sub, tenant: claims.tenant, role: claims.role })
  })

  // hos-d5: XXE look-alike — DOCTYPE/DTD processing disabled, entities never expanded or fetched.
  router.post('/api/v1/import/xml/strict', xmlImportHandler(ctx, { strict: true }))

  // hos-d6: cache-deception look-alike — wildcard static catalog, `Cache-Control: public`, identical for everyone.
  router.get('/public/catalog/*', c => {
    const name = c.params.splat ?? ''
    if (name.endsWith('.css')) return sendText(c.res, 200, '/* public plan table styles */\n.plan{font-weight:600}\n', 'text/css; charset=utf-8', { 'cache-control': 'public, max-age=300' })
    sendJson(c.res, 200, { plans: PUBLIC_PLANS }, { 'cache-control': 'public, max-age=300' })
  })
}
