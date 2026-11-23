// SPA bootstrap: load runtime config, manage the session, and route between login and workspace tabs.
// All tabs read the same neutral API; labels and route paths come from the per-seed variant.
import { loadConfig, getConfig, call, setCsrf, routePath, streamUrl } from '/api.js'
import {
  loginView, navView, projectsView, pipelinesView, buildsView, logPanel, secretsView,
  deploymentsView, webhooksView, membersView, searchView, panel, table, statusLine,
} from '/views.js'

const view = document.getElementById('view')
const nav = document.getElementById('nav')
const logoutBtn = document.getElementById('logout')
const who = document.getElementById('who')

let currentTab = 'projects'
let logStream = null

function paramName(key) {
  const spec = getConfig().routes[key]
  const m = spec && spec.path.match(/:([A-Za-z0-9_]+)/)
  return m ? m[1] : 'id'
}

function byId(key, id) {
  return { [paramName(key)]: id }
}

async function boot() {
  const cfg = await loadConfig()
  document.title = cfg.labels.brand
  document.getElementById('brand').textContent = cfg.labels.brand
  logoutBtn.addEventListener('click', doLogout)
  const me = await call('me')
  if (me.status === 200 && me.json && me.json.user) {
    if (me.json.csrfToken) setCsrf(me.json.csrfToken)
    await enterWorkspace(me.json.user)
  } else {
    showLogin()
  }
}

function showLogin() {
  nav.classList.add('hidden')
  logoutBtn.classList.add('hidden')
  who.textContent = ''
  const cfg = getConfig()
  view.replaceChildren(loginView(async (email, password, errorEl) => {
    const res = await call('login', { method: 'POST', body: { email, password } })
    if (res.status === 200 && res.json && res.json.ok) {
      if (res.json.csrfToken) setCsrf(res.json.csrfToken)
      await enterWorkspace(res.json.user)
      if (cfg.labels && cfg.labels.tagline) who.title = cfg.labels.tagline
    } else {
      errorEl.hidden = false
      errorEl.textContent = 'Invalid email or password.'
    }
  }))
}

async function enterWorkspace(user) {
  nav.classList.remove('hidden')
  logoutBtn.classList.remove('hidden')
  who.textContent = `${user.email} · ${user.org}`
  const cfg = getConfig()
  nav.replaceChildren(navView(cfg.nav, (tab) => { currentTab = tab; renderTab(tab) }))
  await renderTab(currentTab)
}

async function renderTab(tab) {
  if (logStream) { logStream.close(); logStream = null }
  view.replaceChildren(statusLine('Loading…'))
  try {
    switch (tab) {
      case 'projects': return await renderProjects()
      case 'builds': return await renderBuilds()
      case 'secrets': return await renderSecrets()
      case 'deployments': return await renderDeployments()
      case 'webhooks': return await renderWebhooks()
      case 'members': return await renderMembers()
      case 'search': return renderSearch()
      default: return await renderProjects()
    }
  } catch (err) {
    view.replaceChildren(statusLine(`Failed to load: ${err.message}`, true))
  }
}

async function renderProjects() {
  const [projects, pipelines] = await Promise.all([call('projects.list'), call('pipelines.list')])
  const items = (projects.json && projects.json.items) || []
  const pipes = (pipelines.json && pipelines.json.items) || []
  const container = document.createElement('div')
  container.className = 'stack'
  container.append(projectsView(items, async (name) => {
    if (!name) return
    await call('projects.create', { method: 'POST', body: { name } })
    await renderTab('projects')
  }))
  container.append(pipelinesView(pipes))
  view.replaceChildren(container)
}

async function renderBuilds() {
  const res = await call('builds.list')
  const items = (res.json && res.json.items) || []
  const container = document.createElement('div')
  container.className = 'stack'
  const log = logPanel()
  container.append(buildsView(items, (build) => {
    log.reset()
    if (logStream) logStream.close()
    logStream = new EventSource(streamUrl('streams.build', byId('streams.build', build.id)), { withCredentials: true })
    logStream.addEventListener('ready', (ev) => log.appendLine(`connected: ${ev.data}`))
    logStream.addEventListener('log', (ev) => {
      try { log.appendLine(JSON.parse(ev.data).line) } catch { log.appendLine(ev.data) }
    })
    logStream.onerror = () => { log.appendLine('[stream closed]') }
  }))
  container.append(log)
  view.replaceChildren(container)
}

async function renderSecrets() {
  const res = await call('secrets.list')
  const container = document.createElement('div')
  container.className = 'stack'
  container.append(secretsView((res.json && res.json.items) || [], {
    async onCreate(name, value) {
      if (!name) return
      await call('secrets.create', { method: 'POST', body: { name, value } })
      await renderTab('secrets')
    },
    async onDelete(id) {
      await call('secrets.delete', { method: 'DELETE', pathParams: byId('secrets.delete', id) })
      await renderTab('secrets')
    },
    async onBatch(ids) {
      if (!ids.length) return
      await call('secrets.batch', { method: 'POST', body: { ids, patch: { value: 'rotated-at-once' } } })
      await renderTab('secrets')
    },
  }))
  view.replaceChildren(container)
}

async function renderDeployments() {
  const res = await call('deployments.list')
  const items = (res.json && res.json.items) || []
  const container = document.createElement('div')
  container.className = 'stack'
  const act = (key) => async (id) => {
    await call(key, { method: 'POST', pathParams: byId(key, id) })
    await renderTab('deployments')
  }
  container.append(deploymentsView(items, {
    onApprove: act('deployments.approve'),
    onSchedule: act('deployments.schedule'),
    onDispute: act('deployments.dispute'),
    onRelease: act('deployments.release'),
  }))
  view.replaceChildren(container)
}

async function renderWebhooks() {
  const res = await call('webhooks.list')
  const items = (res.json && res.json.items) || []
  const container = document.createElement('div')
  container.className = 'stack'
  const deliveries = panel('Delivery history')
  container.append(webhooksView(items, {
    async onCreate(url, events) {
      if (!url) return
      await call('webhooks.create', { method: 'POST', body: { url, events } })
      await renderTab('webhooks')
    },
    async onDeliveries(id) {
      const r = await call('webhooks.deliveries', { pathParams: byId('webhooks.deliveries', id) })
      const rows = ((r.json && r.json.items) || []).map((d) => [d.event, d.status, d.detail])
      deliveries.querySelector('.body').replaceChildren(table(['Event', 'Status', 'Detail'], rows))
    },
  }))
  container.append(deliveries)
  view.replaceChildren(container)
}

async function renderMembers() {
  const res = await call('members.list')
  const items = (res.json && res.json.items) || []
  const container = document.createElement('div')
  container.className = 'stack'
  container.append(membersView(items, {
    async onInvite(email, role) {
      if (!email) return
      await call('members.invite', { method: 'POST', body: { email, role } })
      await renderTab('members')
    },
  }))
  view.replaceChildren(container)
}

function renderSearch() {
  const node = searchView(async (q) => {
    const res = await call('search.query', { query: { q } })
    node.renderResults((res.json && res.json.items) || [])
  }, async (prefix) => {
    const res = await call('search.facets', { query: { prefix } })
    if (res.json) node.renderFacets(res.json)
  })
  view.replaceChildren(node)
}

async function doLogout() {
  await call('logout', { method: 'POST' }).catch(() => undefined)
  setCsrf(null)
  showLogin()
}

boot().catch((err) => {
  view.replaceChildren(statusLine(`Workspace failed to load: ${err.message}`, true))
})

export { routePath }
