// Discovery surface, HTML forms, the multi-step browser wizard (xben-16) and the cache challenges (xben-24).
import { escapeHtml, send, sendHtml, sendJson } from './core.ts'
import type { Ctx } from './core.ts'
import { ensureSession } from './routes-sqli.ts'
import { graphqlSdl } from './routes-graphql.ts'

const appJs = `// xben-25 demo storefront client
async function search(term) {
  return fetch('/api/search', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ term: term }) })
}
async function getOrder(id) { return fetch('/api/orders/' + id) }
async function postComment(text) {
  return fetch('/api/comments', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ body: text }) })
}
async function updateProfile(p) {
  return fetch('/api/profile', { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: p.name, email: p.email }) })
}
async function xmlLookup(n) {
  return fetch('/api/xml/lookup', { method: 'POST', headers: { 'Content-Type': 'application/xml' }, body: '<lookup><name>' + n + '</name></lookup>' })
}
async function importXml(x) {
  return fetch('/api/xml/import', { method: 'POST', headers: { 'Content-Type': 'application/xml' }, body: x })
}
const PRODUCTS_QUERY = 'query($category: String){ products(category: $category){ id name category } }'
const INVOICE_QUERY = 'query($id: ID!){ invoice(id: $id){ id total memo owner { id name } } }'
async function gql(query, variables) {
  return fetch('/graphql', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: query, variables: variables }) })
}
`

function openApiDoc(origin: string): unknown {
  const q = (name: string, where = 'query') => ({ name, in: where, required: false, schema: { type: 'string' } })
  const jsonBody = (props: Record<string, unknown>) => ({ required: true, content: { 'application/json': { schema: { type: 'object', properties: props } } } })
  return {
    openapi: '3.0.3',
    info: { title: 'XBEN-25 storefront API', version: '1.0.0' },
    servers: [{ url: origin }],
    paths: {
      '/api/products': { get: { parameters: [q('category')] } },
      '/api/search': { post: { requestBody: jsonBody({ term: { type: 'string' } }) } },
      '/api/items/{sku}': { get: { parameters: [q('sku', 'path')] } },
      '/api/track': { get: { parameters: [q('X-Tracking-Id', 'header')] } },
      '/api/orders/lookup': { get: { parameters: [q('ref')] } },
      '/api/orders/{id}': { get: { parameters: [q('id', 'path')], security: [{ bearer: [] }] } },
      '/api/admin/users/{id}/promote': { post: { parameters: [q('id', 'path')], security: [{ bearer: [] }] } },
      '/api/fetch': { get: { parameters: [q('url')] } },
      '/api/comments': { get: {}, post: { requestBody: jsonBody({ body: { type: 'string' } }), security: [{ bearer: [] }] } },
      '/api/jwt/profile': { get: { security: [{ bearer: [] }] } },
      '/api/jwt/jku-profile': { get: { security: [{ bearer: [] }] } },
      '/api/files/download': { get: { parameters: [q('name')] } },
      '/api/profile': { get: { security: [{ bearer: [] }] }, patch: { requestBody: jsonBody({ name: { type: 'string' }, email: { type: 'string' } }), security: [{ bearer: [] }] } },
    },
  }
}

function homePage(ctx: Ctx, csrf: string): string {
  const oauth = '/oauth/authorize?client_id=web&response_type=code&redirect_uri=http%3A%2F%2Fapp.client.test%2Fcb&state=s1&code_challenge_method=S256&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
  return `<!doctype html><html><head><title>XBEN-25 Storefront</title><script src="/app.js"></script></head><body>
<h1>XBEN-25 Storefront</h1>
<nav>
<a href="/greet?name=guest">Greeting</a>
<a href="/search?q=hello">Search</a>
<a href="/api/products?category=books">Books</a>
<a href="${oauth}">Sign in with partner</a>
<a href="/api/files/download?name=report.txt">Download report</a>
<a href="/cache/banner">Banner</a>
<a href="/account/summary">Account summary</a>
<a href="/api/diagnostics/ping?host=127.0.0.1">Diagnostics</a>
<a href="/wizard">Profile wizard</a>
<a href="/comments">Comments</a>
</nav>
<form method="POST" action="/search/form"><input type="text" name="q" value="manuals"><button type="submit">Legacy search</button></form>
<form method="POST" action="/account/search"><input type="hidden" name="_csrf" value="${escapeHtml(csrf)}"><input type="text" name="q" value="invoices"><button type="submit">Account search</button></form>
</body></html>`
}

function wizardPage(): string {
  return `<!doctype html><html><head><title>Profile wizard</title></head><body>
<h1>Profile wizard</h1>
<section id="step1"><label>Display name <input id="display-name" name="display-name" type="text"></label>
<button id="continue" type="button">Continue</button></section>
<section id="step2" hidden><h2>Step 2</h2><button id="preview" type="button">Preview</button><div id="preview-out"></div></section>
<script>
var state = { name: '' }
document.getElementById('continue').addEventListener('click', function () {
  state.name = document.getElementById('display-name').value
  document.getElementById('step2').hidden = false
})
document.getElementById('preview').addEventListener('click', function () {
  fetch('/api/wizard/confirm?name=' + encodeURIComponent(state.name)).then(function (r) { return r.json() }).then(function (j) {
    document.getElementById('preview-out').innerHTML = '<p>Welcome, ' + state.name + '</p>' + (j.marker ? '<span id="marker">' + j.marker + '</span>' : '')
  })
})
</script></body></html>`
}

function cacheHeaders(entryAgeSec: number, hit: boolean): Record<string, string> {
  return { 'Cache-Control': 'public, max-age=60', 'X-Cache': hit ? 'HIT' : 'MISS', ...(hit ? { Age: String(Math.max(5, entryAgeSec)) } : {}) }
}

const cacheTtlMs = 60_000

async function handleCache(ctx: Ctx): Promise<boolean> {
  const { method, path, url, state } = ctx
  if (method !== 'GET') return false
  const key = path + url.search
  const now = Date.now()

  if (path === '/cache/banner') {
    const hit = state.cache.get(key)
    if (hit && now - hit.storedAt < cacheTtlMs) return send(ctx, hit.status, hit.contentType, hit.body, cacheHeaders(Math.floor((now - hit.storedAt) / 1000), true))
    // Unkeyed header reflected into the cached page: the poisoning primitive.
    const override = [ctx.headers['x-forwarded-host'], ctx.headers['x-host']].find(v => typeof v === 'string') as string | undefined
    const host = override ?? String(ctx.headers.host ?? 'localhost')
    const body = `<!doctype html><html><body><a id="promo" href="http://${host}/promo">Today's promo</a><script src="//${host}/static/banner.js"></script>${override ? `<!-- host-override:${ctx.markers['xben-24']} -->` : ''}</body></html>`
    state.cache.set(key, { status: 200, contentType: 'text/html; charset=utf-8', body, storedAt: now })
    return send(ctx, 200, 'text/html; charset=utf-8', body, cacheHeaders(0, false))
  }

  // Cache deception: private page is cached when the URL "looks static".
  if (path === '/account/summary' || path.startsWith('/account/summary/')) {
    const staticLike = /\.(?:css|js|png|ico|svg)$/i.test(path)
    const cached = state.cache.get(key)
    if (!ctx.auth.userId) {
      if (staticLike && cached && now - cached.storedAt < cacheTtlMs) {
        return send(ctx, 200, cached.contentType, `${cached.body}<!-- cached-private:${ctx.markers['xben-24']} -->`, cacheHeaders(Math.floor((now - cached.storedAt) / 1000), true))
      }
      return sendJson(ctx, 401, { error: 'authentication required' })
    }
    const email = ctx.auth.userId === 'u-1000' ? 'admin@xben.test' : ctx.state.profiles.get(ctx.auth.userId)?.email ?? 'unknown'
    const body = `<!doctype html><html><body><h1>Account summary</h1><p>Signed in as ${escapeHtml(email)}</p><p>Balance: 1234.56</p></body></html>`
    if (staticLike) state.cache.set(key, { status: 200, contentType: 'text/html; charset=utf-8', body, storedAt: now })
    return send(ctx, 200, 'text/html; charset=utf-8', body, staticLike ? cacheHeaders(0, false) : {})
  }
  return false
}

export async function handleWeb(ctx: Ctx): Promise<boolean> {
  const { method, path } = ctx
  if (method === 'GET' && path === '/') {
    const session = ensureSession(ctx)
    return sendHtml(ctx, 200, homePage(ctx, session.csrf), session.setCookie ? { 'Set-Cookie': session.setCookie } : {})
  }
  if (method === 'GET' && path === '/account/search-form') {
    const session = ensureSession(ctx)
    return sendHtml(ctx, 200, `<!doctype html><html><body><form method="POST" action="/account/search"><input type="hidden" name="_csrf" value="${escapeHtml(session.csrf)}"><input name="q" value="invoices"><button>Go</button></form></body></html>`, session.setCookie ? { 'Set-Cookie': session.setCookie } : {})
  }
  if (method === 'GET' && path === '/robots.txt') {
    return send(ctx, 200, 'text/plain; charset=utf-8', 'User-agent: *\nDisallow: /api/xml/\nDisallow: /api/admin/\nDisallow: /account/search-form\nAllow: /comments\n')
  }
  if (method === 'GET' && path === '/sitemap.xml') {
    const urls = ['/', '/search?q=hello', '/comments', '/wizard', '/cache/banner', '/account/summary']
    const xml = `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.map(u => `<url><loc>${escapeHtml(ctx.origin + u)}</loc></url>`).join('')}</urlset>`
    return send(ctx, 200, 'application/xml; charset=utf-8', xml)
  }
  if (method === 'GET' && (path === '/openapi.json' || path === '/swagger.json')) {
    return path === '/openapi.json' ? sendJson(ctx, 200, openApiDoc(ctx.origin)) : sendJson(ctx, 404, { error: 'not found' })
  }
  if (method === 'GET' && path === '/app.js') return send(ctx, 200, 'application/javascript; charset=utf-8', appJs)
  if (method === 'GET' && path === '/graphql.sdl') return send(ctx, 200, 'text/plain; charset=utf-8', graphqlSdl)
  if (method === 'GET' && path === '/.well-known/openid-configuration') {
    return sendJson(ctx, 200, {
      issuer: ctx.origin,
      authorization_endpoint: `${ctx.origin}/oauth/authorize`,
      jwks_uri: `${ctx.origin}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256', 'plain'],
    })
  }
  if (method === 'GET' && path === '/.well-known/jwks.json') return sendJson(ctx, 200, { keys: [] })
  if (method === 'GET' && path === '/wizard') return sendHtml(ctx, 200, wizardPage())
  if (method === 'GET' && path === '/api/wizard/confirm') {
    const name = ctx.url.searchParams.get('name') ?? ''
    return sendJson(ctx, 200, { ok: true, ...(/[<>]/.test(name) ? { marker: ctx.markers['xben-16'] } : {}) })
  }
  if (method === 'GET' && path === '/health') return sendJson(ctx, 200, { ok: true })
  return handleCache(ctx)
}
