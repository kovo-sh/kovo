// Shopflow single-page app. Loads the runtime route map from /app-config.json and drives the
// storefront and merchant back-office against the JSON API.
import { renderReview } from '/review.js'

let config = { apiPrefix: '/api', routes: {} }
let csrf = null

async function api(routeKey, opts = {}, values = {}) {
  const spec = config.routes[routeKey]
  const raw = typeof spec === 'string' ? spec : (spec && spec.path) || ''
  if (!raw) throw new Error('unknown route ' + routeKey)
  const path = raw.replace(/:([A-Za-z0-9_]+)/g, (_, key) => encodeURIComponent(values[key] || '1'))
  const headers = Object.assign({ 'content-type': 'application/json' }, opts.headers || {})
  if (csrf) headers['x-csrf-token'] = csrf
  const res = await fetch(path, Object.assign({ headers }, opts))
  return res.json().catch(() => ({}))
}

function setWho(text) {
  document.getElementById('who').textContent = text
}

async function signin() {
  const email = document.getElementById('email').value
  const password = document.getElementById('password').value
  const spec = config.routes.login
  const loginPath = typeof spec === 'string' ? spec : (spec && spec.path)
  if (!loginPath) throw new Error('login route unavailable')
  const res = await fetch(loginPath, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password }),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) { document.getElementById('loginError').textContent = 'Sign in failed'; return }
  csrf = data.csrf
  setWho(`${data.persona} @ ${data.store}`)
  document.getElementById('login').hidden = true
  document.getElementById('view').hidden = false
  showView('store')
}

async function showView(view) {
  const el = document.getElementById('view')
  el.innerHTML = '<p>Loading…</p>'
  if (view === 'store') {
    const data = await api('listProducts')
    el.innerHTML = '<h2>Catalog</h2>' + (data.products || []).map((p) =>
      `<div class="row"><span>${p.title}</span><span>$${(p.price / 100).toFixed(2)}</span></div>`).join('')
  } else if (view === 'orders') {
    const data = await api('listOrders')
    el.innerHTML = '<h2>Orders</h2>' + (data.orders || []).map((o) =>
      `<div class="row"><span>${o.external_id}</span><span>${o.status}</span></div>`).join('')
  } else if (view === 'reviews') {
    const data = await api('moderationQueue', { headers: { accept: 'text/html' } })
    el.innerHTML = '<h2>Moderation queue</h2>'
    const box = document.createElement('div')
    // Reviews are stored as rich HTML and shown to moderators as-is.
    for (const item of data.items || []) box.appendChild(renderReview(item))
    el.appendChild(box)
  } else if (view === 'settings') {
    const data = await api('getSettings')
    el.innerHTML = '<h2>Settings</h2><pre>' + JSON.stringify(data.settings || {}, null, 2) + '</pre>'
  } else if (view === 'imports') {
    el.innerHTML = `
      <h2>Catalog imports</h2>
      <label>Product ID <input id="import-product" value=""></label>
      <label>Image URL <input id="import-image" value="https://cdn.example.test/image.png"></label>
      <button id="import-image-run">Import image</button>
      <label>Label template URL <input id="import-template" value="https://carrier.example.test/label.xml"></label>
      <button id="import-label-run">Import shipping label</button>
      <pre id="import-out"></pre>`
    document.getElementById('import-image-run').addEventListener('click', async () => {
      const field = (config.params && config.params.imageUrl) || 'imageUrl'
      const body = {}
      body[field] = document.getElementById('import-image').value
      const productId = document.getElementById('import-product').value
      const r = await api('importProductImage', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
      }, { productId })
      document.getElementById('import-out').textContent = JSON.stringify(r)
    })
    document.getElementById('import-label-run').addEventListener('click', async () => {
      const field = (config.params && config.params.templateUrl) || 'templateUrl'
      const body = {}
      body[field] = document.getElementById('import-template').value
      const r = await api('importShippingLabel', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
      })
      document.getElementById('import-out').textContent = JSON.stringify(r)
    })
  }
}

async function boot() {
  config = await fetch('/app-config.json').then((r) => r.json()).catch(() => config)
  document.getElementById('signin').addEventListener('click', signin)
  for (const btn of document.querySelectorAll('nav button')) {
    btn.addEventListener('click', () => showView(btn.dataset.view))
  }
}

boot()
