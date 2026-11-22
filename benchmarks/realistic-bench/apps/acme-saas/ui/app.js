// SPA bootstrap: load runtime config, manage the session, and route between login and the dashboard.
import { loadConfig, call, setCsrf } from '/api.js'
import { loginView, dashboardView, navView } from '/views.js'

const view = document.getElementById('view')
const nav = document.getElementById('nav')
const logoutBtn = document.getElementById('logout')

const TABS = ['Dashboard', 'Projects', 'Invoices', 'Members', 'Files', 'Reports', 'Settings']

async function boot() {
  await loadConfig()
  logoutBtn.addEventListener('click', doLogout)
  const me = await call('me')
  if (me.status === 200 && me.json && me.json.user) {
    if (me.json.csrfToken) setCsrf(me.json.csrfToken)
    await showDashboard()
  } else {
    showLogin()
  }
}

function showLogin() {
  nav.classList.add('hidden')
  logoutBtn.classList.add('hidden')
  view.replaceChildren(loginView(async (email, password, errorEl) => {
    const res = await call('login', { method: 'POST', body: { email, password } })
    if (res.status === 200 && res.json && res.json.ok) {
      if (res.json.csrfToken) setCsrf(res.json.csrfToken)
      await showDashboard()
    } else {
      errorEl.hidden = false
      errorEl.textContent = 'Invalid email or password.'
    }
  }))
}

async function showDashboard() {
  nav.classList.remove('hidden')
  logoutBtn.classList.remove('hidden')
  nav.replaceChildren(...navView(TABS, () => {}).childNodes)
  const [projects, invoices, members] = await Promise.all([
    call('listProjects'), call('listInvoices'), call('listMembers'),
  ])
  view.replaceChildren(dashboardView({
    projects: (projects.json && projects.json.items) || [],
    invoices: (invoices.json && invoices.json.items) || [],
    members: (members.json && members.json.items) || [],
  }))
}

async function doLogout() {
  await call('logout', { method: 'POST' })
  showLogin()
}

boot().catch((err) => {
  view.innerHTML = `<p class="error">Console failed to load: ${err.message}</p>`
})
