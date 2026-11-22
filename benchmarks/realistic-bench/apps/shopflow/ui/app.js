// Shopflow single-page app. Loads the runtime route map from /app-config.json and drives the
// storefront and merchant back-office against the JSON API.
import { renderReview } from '/review.js'

let config = { apiPrefix: '/api', routes: {} }
let csrf = null

async function api(routeKey, opts = {}) {
  const path = config.routes[routeKey]
  if (!path) throw new Error('unknown route ' + routeKey)
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
  const res = await fetch(config.routes.login, {
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
