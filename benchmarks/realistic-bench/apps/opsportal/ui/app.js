// OpsPortal SPA. Loads the per-seed route map from /app-config.json and renders the operations views.
// Ticket notes and log lines are rendered as rich HTML via innerHTML so operators can use inline
// formatting in their escalation context.
let config = { apiPrefix: '/api', routes: {} }
const app = document.getElementById('app')
const nav = document.getElementById('nav')

const path = (key) => (config.routes[key] ? config.routes[key].path : null)

async function api(key, init) {
  const p = path(key)
  if (!p) return { error: 'route_unavailable' }
  const res = await fetch(p, init)
  const text = await res.text()
  try { return JSON.parse(text) } catch { return { html: text } }
}

async function boot() {
  try { config = await (await fetch('/app-config.json')).json() } catch { /* keep defaults */ }
  const me = await api('me')
  if (me && me.authenticated) { showNav(); render('dashboard') }
  else renderLogin()
}

function showNav() { nav.hidden = false }

function renderLogin() {
  nav.hidden = true
  app.innerHTML = `
    <section class="card">
      <h1>Sign in</h1>
      <label>Email <input id="email" type="email" autocomplete="username"></label>
      <label>Password <input id="password" type="password" autocomplete="current-password"></label>
      <button id="signin">Sign in</button>
      <p id="err" class="err"></p>
    </section>`
  document.getElementById('signin').addEventListener('click', async () => {
    const email = document.getElementById('email').value
    const password = document.getElementById('password').value
    const r = await api('login', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
    if (r && r.ok) { showNav(); render('dashboard') }
    else document.getElementById('err').textContent = 'Invalid credentials'
  })
}

async function render(view) {
  app.innerHTML = `<p class="muted">Loading ${view}…</p>`
  if (view === 'dashboard') return renderDashboard()
  if (view === 'tickets') return renderList('Tickets', 'ticketList', 'subject')
  if (view === 'accounts') return renderList('Accounts', 'accountList', 'name')
  if (view === 'reports') return renderReports()
  if (view === 'logs') return renderLogs()
  if (view === 'diagnostics') return renderDiagnostics()
  if (view === 'webhooks') return renderWebhooks()
  if (view === 'integrations') return renderIntegrations()
}

async function renderDashboard() {
  const s = await api('dashboardSummary')
  app.innerHTML = `
    <section class="card">
      <h1>Dashboard</h1>
      <div class="stats">
        <div class="stat"><span>${s.openTickets ?? 0}</span>Open tickets</div>
        <div class="stat"><span>${s.accounts ?? 0}</span>Accounts</div>
        <div class="stat"><span>${s.tenant ?? '—'}</span>Team</div>
      </div>
    </section>`
}

async function renderList(title, key, field) {
  const r = await api(key)
  const items = (r.items || []).map((it) => `<li>${esc(it[field] || it.ext_id)}</li>`).join('')
  app.innerHTML = `<section class="card"><h1>${title}</h1><ul class="list">${items}</ul></section>`
}

async function renderReports() {
  app.innerHTML = `
    <section class="card">
      <h1>Report builder</h1>
      <textarea id="layout" rows="4">Report for {{ account }}: {{ total }} open tickets</textarea>
      <button id="preview">Preview</button>
      <div id="out" class="preview"></div>
    </section>`
  document.getElementById('preview').addEventListener('click', async () => {
    const field = (config.params && config.params.templateSrc) || 'template'
    const body = {}
    body[field] = document.getElementById('layout').value
    const r = await api('reportRender', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    })
    document.getElementById('out').innerHTML = r.html || ''
  })
}

async function renderLogs() {
  const r = await api('logList')
  const files = (r.files || []).map((f) => `<li>${esc(f)}</li>`).join('')
  app.innerHTML = `<section class="card"><h1>Logs</h1><ul class="list">${files}</ul></section>`
}

async function renderDiagnostics() {
  app.innerHTML = `
    <section class="card">
      <h1>Diagnostics</h1>
      <label>Host <input id="host" value="127.0.0.1"></label>
      <button id="run">Run probe</button>
      <pre id="diagout" class="preview"></pre>
    </section>`
  document.getElementById('run').addEventListener('click', async () => {
    const field = (config.params && config.params.host) || 'host'
    const body = {}
    body[field] = document.getElementById('host').value
    const r = await api('diagRun', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    })
    document.getElementById('diagout').textContent = r.output || r.error || ''
  })
}

function esc(v) {
  return String(v).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])
}

async function renderWebhooks() {
  app.innerHTML = `
    <section class="card">
      <h1>Outbound webhooks</h1>
      <label>Endpoint URL <input id="webhook-url" value="https://example.test/hook"></label>
      <button id="webhook-save">Save target</button>
      <p id="webhook-out" class="muted"></p>
    </section>`
  document.getElementById('webhook-save').addEventListener('click', async () => {
    const field = (config.params && config.params.webhookUrl) || 'url'
    const body = {}
    body[field] = document.getElementById('webhook-url').value
    const r = await api('webhookCreate', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    })
    document.getElementById('webhook-out').textContent = r.id ? `Saved ${r.id}` : (r.error || 'Save failed')
  })
}

async function renderIntegrations() {
  app.innerHTML = `
    <section class="card">
      <h1>Connector check</h1>
      <label>Connector URL <input id="integration-url" value="https://example.test/status"></label>
      <button id="integration-run">Test connection</button>
      <p id="integration-out" class="muted"></p>
    </section>`
  document.getElementById('integration-run').addEventListener('click', async () => {
    const field = (config.params && config.params.webhookUrl) || 'url'
    const body = {}
    body[field] = document.getElementById('integration-url').value
    const r = await api('integrationFetch', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    })
    document.getElementById('integration-out').textContent = r.reachable ? 'Connector reachable' : 'Connector unavailable'
  })
}

nav.addEventListener('click', (e) => {
  const view = e.target && e.target.getAttribute('data-view')
  if (view) render(view)
})
document.getElementById('logout').addEventListener('click', async () => {
  await api('logout', { method: 'POST' })
  renderLogin()
})

boot()
