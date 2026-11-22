// Public shell: landing page, client bundle, discovery documents, DOM-sink demo page.
import { ACTION_IDS } from './config.mjs'
import { issueCsrf } from './csrf.mjs'
import { publicJwks } from './auth.mjs'
import { sendHtml, sendJson, sendText } from './http-util.mjs'
import { marker } from './markers.mjs'

const OPENAPI_OPERATIONS = [
  { path: '/api/v1/invoices', method: 'get', summary: 'List invoices for the caller tenant' },
  { path: '/api/v1/invoices/{id}', method: 'get', summary: 'Fetch an invoice', params: [{ name: 'id', in: 'path', type: 'string' }] },
  { path: '/api/v2/invoices/{id}', method: 'get', summary: 'Fetch an invoice (tenant scoped)', params: [{ name: 'id', in: 'path', type: 'string' }] },
  { path: '/api/v1/sales-orders', method: 'get', summary: 'Search sales orders by reference', params: [{ name: 'ref', in: 'query', type: 'string' }] },
  { path: '/api/v1/profile', method: 'get', summary: 'Current user profile' },
  { path: '/api/v1/profile', method: 'patch', summary: 'Update profile', body: { displayName: 'string', marketingOptIn: 'boolean' } },
  { path: '/api/v1/org', method: 'get', summary: 'Current organisation' },
  { path: '/api/v1/session', method: 'get', summary: 'Describe the current session (v1)' },
  { path: '/api/v2/session', method: 'get', summary: 'Describe the current session (v2)' },
  { path: '/api/v1/admin/feature-flags', method: 'get', summary: 'List feature flags (admin)' },
  { path: '/api/v1/admin/feature-flags', method: 'post', summary: 'Toggle a feature flag (admin)', body: { flag: 'string', enabled: 'boolean' } },
  { path: '/api/v1/checkout/orders', method: 'post', summary: 'Create a draft order', body: { sku: 'string', qty: 'integer' } },
  { path: '/api/v1/checkout/orders/{id}/pay', method: 'post', summary: 'Pay for an order', params: [{ name: 'id', in: 'path', type: 'string' }], body: { paymentToken: 'string' } },
  { path: '/api/v1/checkout/orders/{id}/confirm', method: 'post', summary: 'Confirm a paid order', params: [{ name: 'id', in: 'path', type: 'string' }] },
  { path: '/api/v1/credits', method: 'get', summary: 'Credit balance' },
  { path: '/api/v1/credits/vouchers', method: 'post', summary: 'Mint a single-use credit voucher' },
  { path: '/api/v1/credits/redeem', method: 'post', summary: 'Redeem a voucher', body: { code: 'string' } },
  { path: '/api/v1/comments', method: 'post', summary: 'Post a project comment', body: { projectId: 'string', body: 'string' } },
  { path: '/api/v1/comments', method: 'get', summary: 'List project comments', params: [{ name: 'projectId', in: 'query', type: 'string' }] },
  { path: '/api/v1/notes', method: 'post', summary: 'Post a project note', body: { projectId: 'string', body: 'string' } },
  { path: '/api/v1/notifications/preview', method: 'post', summary: 'Preview a notification template', body: { template: 'string', name: 'string' } },
  { path: '/api/v1/exports', method: 'get', summary: 'List export files' },
  { path: '/api/v1/exports/download', method: 'get', summary: 'Download an export file', params: [{ name: 'file', in: 'query', type: 'string' }] },
  { path: '/api/v1/catalog/search', method: 'get', summary: 'Search the product catalog', params: [{ name: 'q', in: 'query', type: 'string' }] },
]

function buildOpenApi() {
  const paths = {}
  for (const op of OPENAPI_OPERATIONS) {
    paths[op.path] ??= {}
    const operation = {
      summary: op.summary,
      parameters: op.params ?? [],
      responses: { 200: { description: 'OK' } },
    }
    if (op.body) {
      operation.requestBody = {
        content: {
          'application/json': {
            schema: { type: 'object', properties: Object.fromEntries(Object.entries(op.body).map(([k, t]) => [k, { type: t }])) },
          },
        },
      }
    }
    paths[op.path][op.method] = operation
  }
  return {
    openapi: '3.0.3',
    info: { title: 'Orbit Workspace API', version: '1.4.0' },
    servers: [{ url: '/' }],
    components: { securitySchemes: { bearer: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } } },
    security: [{ bearer: [] }],
    paths,
  }
}

function clientBundle() {
  return `/* Orbit Workspace client bundle v1.4.0 */
window.__ORBIT_BUILD__ = '${marker('hos-18')}';
const authHeaders = () => ({ 'Content-Type': 'application/json', Authorization: 'Bearer ' + (localStorage.getItem('orbit_token') || '') });

export async function loadInvoices() { return fetch('/api/v1/invoices', { headers: authHeaders() }).then(r => r.json()); }
export async function trackEvent(name) {
  return fetch('/api/v1/analytics/query', { method: 'POST', headers: authHeaders(), body: JSON.stringify({ filter: { name } }) });
}
export async function registerWebhook(url, event) {
  return fetch('/api/v1/webhooks', { method: 'POST', headers: authHeaders(), body: JSON.stringify({ url, event }) });
}
export async function partnerLedger() { return fetch('/api/v1/partner/ledger', { headers: authHeaders() }).then(r => r.json()); }
export async function importCatalog(xml) {
  return fetch('/api/v1/import/xml', { method: 'POST', headers: { 'Content-Type': 'application/xml' }, body: xml });
}
export async function lookupUser(id) {
  const query = 'query($id: ID!) { user(id: $id) { id name invoices { id number total memo } } }';
  return fetch('/graphql', { method: 'POST', headers: authHeaders(), body: JSON.stringify({ query, variables: { id } }) }).then(r => r.json());
}
export async function findProducts(sku) {
  const query = 'query($sku: String) { products(sku: $sku) { id sku name price } }';
  return fetch('/graphql', { method: 'POST', headers: authHeaders(), body: JSON.stringify({ query, variables: { sku } }) }).then(r => r.json());
}

// Server actions (App Router)
const updateOrgPlan = createServerReference("${ACTION_IDS.updateOrgPlan}", callServer, void 0, "updateOrgPlan");
const exportOrgSummary = createServerReference("${ACTION_IDS.exportOrgSummary}", callServer, void 0, "exportOrgSummary");
export async function changePlan(orgId, plan) {
  return fetch('/_actions/updateOrgPlan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Next-Action': '${ACTION_IDS.updateOrgPlan}' },
    body: JSON.stringify([orgId, plan]),
  });
}
`
}

function landingHtml(csrf) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Orbit Workspace</title>
  <meta name="generator" content="Next.js">
  <script src="/app.js" defer></script>
</head>
<body>
  <header><h1>Orbit Workspace</h1>
  <nav>
    <a href="/app/members">Members</a>
    <a href="/app/search?q=roadmap">Search</a>
    <a href="/app/account/profile">Account</a>
    <a href="/app/projects/p_acme_1/activity">Activity</a>
    <a href="/app/projects/p_acme_1/notes">Notes</a>
    <a href="/public/catalog/plans.json">Plans</a>
    <a href="/openapi.json">API docs</a>
  </nav></header>
  <main>
    <h2>Find a teammate</h2>
    <form action="/app/members/search" method="post">
      <input type="hidden" name="_csrf" value="${csrf}">
      <input type="text" name="member_id" placeholder="Member id">
      <button type="submit">Find</button>
    </form>
    <h2>Search workspace</h2>
    <form action="/app/search" method="get">
      <input type="text" name="q" placeholder="Search">
      <button type="submit">Search</button>
    </form>
  </main>
</body>
</html>`
}

function searchPageHtml() {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Search - Orbit Workspace</title></head>
<body><h1>Search</h1><div id="results"></div><script src="/static/search.js"></script></body></html>`
}

export function register(router, ctx) {
  router.get('/health', c => sendJson(c.res, 200, { status: 'ok', service: 'orbit-workspace' }))

  router.get('/', c => sendHtml(c.res, 200, landingHtml(issueCsrf(ctx, c.res))))

  router.get('/robots.txt', c => sendText(c.res, 200, [
    'User-agent: *',
    'Allow: /app/',
    'Disallow: /api/v1/admin/',
    'Disallow: /internal/',
    'Sitemap: /sitemap.xml',
    '',
  ].join('\n')))

  router.get('/sitemap.xml', c => sendText(c.res, 200, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/app/members</loc></url>
  <url><loc>/app/search?q=roadmap</loc></url>
  <url><loc>/app/projects/p_acme_1/activity</loc></url>
  <url><loc>/graphql</loc></url>
</urlset>
`, 'application/xml; charset=utf-8'))

  router.get('/openapi.json', c => sendJson(c.res, 200, buildOpenApi()))

  router.get('/app.js', c => sendText(c.res, 200, clientBundle(), 'application/javascript; charset=utf-8'))

  router.get('/.well-known/jwks.json', c => sendJson(c.res, 200, publicJwks()))

  router.get('/.well-known/openid-configuration', c => sendJson(c.res, 200, {
    issuer: 'https://orbit-workspace.lab',
    jwks_uri: '/.well-known/jwks.json',
    id_token_signing_alg_values_supported: ['HS256', 'RS256'],
    response_types_supported: ['code'],
  }))

  // hos-18: DOM-based XSS — the server never reflects `q`; the client bundle writes it into innerHTML.
  router.get('/app/search', c => sendHtml(c.res, 200, searchPageHtml()))
  router.get('/static/search.js', c => {
    const body = ctx.fixed('hos-18')
      ? `const q = new URLSearchParams(location.search).get('q') || '';
document.getElementById('results').textContent = 'Results for ' + q;
`
      : `const q = new URLSearchParams(location.search).get('q') || '';
document.getElementById('results').innerHTML = 'Results for ' + q;
`
    sendText(c.res, 200, body, 'application/javascript; charset=utf-8', { 'cache-control': 'no-store' })
  })
}
