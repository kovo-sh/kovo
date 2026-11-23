// LedgerFlow console. Routes, parameter names and business labels are loaded from the per-seed
// runtime config so vocabulary changes never require a UI change. All user data is rendered with
// textContent.
let config = null
let csrf = null
const view = document.getElementById('view')
const nav = document.getElementById('nav')
const logoutBtn = document.getElementById('logout')

async function loadConfig() {
  const res = await fetch('/app-config.json', { credentials: 'same-origin' })
  config = await res.json()
  document.title = `${config.labels.appName} Console`
}

function routePath(key, pathParams = {}, query = {}) {
  const r = config.routes[key]
  if (!r) throw new Error(`unknown route ${key}`)
  let path = r.path
  for (const [name, value] of Object.entries(pathParams)) path = path.replace(`:${name}`, encodeURIComponent(value))
  const qs = Object.entries(query).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')
  return qs ? `${path}?${qs}` : path
}

async function call(key, { pathParams, query, method, body } = {}) {
  const r = config.routes[key]
  const headers = {}
  let payload
  if (body !== undefined) { headers['content-type'] = 'application/json'; payload = JSON.stringify(body) }
  if (csrf) headers['x-csrf-token'] = csrf
  const res = await fetch(routePath(key, pathParams, query), {
    method: method || (r ? r.method : 'GET'), headers, credentials: 'same-origin', body: payload,
  })
  const text = await res.text()
  let json = null
  try { json = JSON.parse(text) } catch { json = null }
  return { status: res.status, json, text }
}

function el(html) {
  const t = document.createElement('template')
  t.innerHTML = html.trim()
  return t.content.firstElementChild
}

function labelState(value) { return (config.labels.states && config.labels.states[value]) || value || '' }
function money(cents) { return `${(Number(cents || 0) / 100).toFixed(2)} ${config.labels.currency}` }
function pill(value) {
  const span = el('<span class="pill"></span>')
  span.textContent = labelState(value)
  if (/paid|complete|approved|settled|accepted/.test(String(value))) span.classList.add('ok')
  if (/pending|queued|draft|open/.test(String(value))) span.classList.add('warn')
  return span
}

function table(headers, rows) {
  const panel = el('<table><thead><tr></tr></thead><tbody></tbody></table>')
  const head = panel.querySelector('thead tr')
  for (const h of headers) { const th = el('<th></th>'); th.textContent = h; head.append(th) }
  const bodyEl = panel.querySelector('tbody')
  for (const cells of rows) {
    const tr = el('<tr></tr>')
    for (const cell of cells) {
      const td = el('<td></td>')
      if (cell instanceof Node) td.append(cell)
      else td.textContent = String(cell ?? '')
      tr.append(td)
    }
    bodyEl.append(tr)
  }
  return panel
}

function panel(title, node) {
  const section = el('<section class="panel"><h2></h2><div class="body"></div></section>')
  section.querySelector('h2').textContent = title
  section.querySelector('.body').append(node)
  return section
}

function showLogin() {
  nav.classList.add('hidden')
  logoutBtn.classList.add('hidden')
  const form = el(`
    <form class="card login">
      <h1>Sign in</h1>
      <label>Email <input name="email" type="email" autocomplete="username" /></label>
      <label>Password <input name="password" type="password" autocomplete="current-password" /></label>
      <button type="submit">Continue</button>
      <p class="error" hidden></p>
      <p class="muted">Use a seeded workspace account.</p>
    </form>`)
  form.addEventListener('submit', async (e) => {
    e.preventDefault()
    const res = await call('login', { method: 'POST', body: { email: form.email.value, password: form.password.value } })
    if (res.status === 200 && res.json && res.json.ok) {
      if (res.json.csrfToken) csrf = res.json.csrfToken
      await showApp()
    } else {
      const err = form.querySelector('.error')
      err.hidden = false
      err.textContent = 'Invalid email or password.'
    }
  })
  view.replaceChildren(form)
}

function showNav(active) {
  nav.classList.remove('hidden')
  logoutBtn.classList.remove('hidden')
  nav.replaceChildren()
  for (const [key, label] of Object.entries(config.labels.nav)) {
    const b = el('<button class="tab"></button>')
    b.textContent = label
    if (key === active) b.classList.add('active')
    b.addEventListener('click', () => showPage(key))
    nav.append(b)
  }
}

async function showPage(page) {
  showNav(page)
  if (page === 'dashboard') return showDashboard()
  if (page === 'invoices') return showInvoices()
  if (page === 'cart') return showCart()
  if (page === 'payouts') return showPayouts()
  if (page === 'invites') return showInvites()
  if (page === 'exports') return showExports()
}

async function showApp() {
  const me = await call('me')
  if (me.status !== 200) return showLogin()
  if (me.json && me.json.csrfToken) csrf = me.json.csrfToken
  await showPage('dashboard')
}

async function showDashboard() {
  const [dash, me] = await Promise.all([call('dashboard'), call('me')])
  const data = (dash.json || {})
  const user = (me.json && me.json.user) || {}
  const wrap = el('<div></div>')
  const stats = el('<div class="grid"></div>')
  const cards = [
    ['Signed in as', user.email || 'unknown'],
    ['Open orders', String((data.orders || []).filter((o) => o.status !== 'paid').length)],
    ['Pending payouts', String((data.payouts || []).filter((p) => p.status === 'pending').length)],
  ]
  for (const [label, value] of cards) {
    const card = el('<div class="stat"><span class="value"></span><span class="label"></span></div>')
    card.querySelector('.value').textContent = value
    card.querySelector('.label').textContent = label
    stats.append(card)
  }
  wrap.append(stats)
  const feed = table(['Actor', 'Action', 'Detail'], (data.activity || []).map((a) => [a.actor, a.action, a.detail]))
  wrap.append(panel('Activity', feed))
  view.replaceChildren(wrap)
}

async function showInvoices() {
  const res = await call('listInvoices')
  const items = (res.json && res.json.items) || []
  const rows = items.map((inv) => {
    const actions = el('<span></span>')
    const pdf = el('<button class="subtle">PDF</button>')
    pdf.addEventListener('click', async () => {
      const r = await call('exportInvoicePdf', { pathParams: { [config.params.invoiceId || 'invoiceId']: inv.id } })
      if (r.status >= 300) alert(`Export failed (${r.status})`)
    })
    actions.append(pdf)
    return [inv.number, money(inv.amount), pill(inv.status), actions]
  })
  view.replaceChildren(panel('Invoices', table(['Number', 'Amount', 'State', ''], rows)))
}

async function showCart() {
  const list = await call('listCarts')
  const carts = (list.json && list.json.items) || []
  const open = carts.find((c) => c.status === 'open') || carts[0]
  const wrap = el('<div></div>')
  if (!open) { wrap.append(panel('Cart', el('<p class="muted">No open cart.</p>'))); view.replaceChildren(wrap); return }
  const rows = (open.items || []).map((item) => {
    const remove = el('<button class="subtle">Remove</button>')
    remove.addEventListener('click', async () => {
      await call('deleteCartItem', { pathParams: { [config.params.cartId || 'cartId']: open.id, [config.params.itemId || 'itemId']: item.id } })
      showCart()
    })
    return [item.name, String(item.qty), money(item.unit), remove]
  })
  const summary = el('<div class="row"></div>')
  const subtotal = el('<span class="muted"></span>')
  subtotal.textContent = `Subtotal ${money(open.subtotal)} · discount ${money(open.discount)} · total ${money(open.total)}`
  summary.append(subtotal)
  const coupon = el('<input placeholder="Coupon code" />')
  const apply = el('<button class="subtle">Apply</button>')
  apply.addEventListener('click', async () => {
    const r = await call('applyCoupon', { pathParams: { [config.params.cartId || 'cartId']: open.id }, body: { code: coupon.value } })
    if (r.status >= 300) alert((r.json && r.json.error) || 'Coupon rejected')
    showCart()
  })
  const checkout = el('<button class="primary">Checkout</button>')
  checkout.addEventListener('click', async () => {
    const r = await call('checkoutCart', { pathParams: { [config.params.cartId || 'cartId']: open.id }, body: {} })
    alert(r.status < 300 ? `Order ${r.json.order} paid` : ((r.json && r.json.error) || `Checkout failed (${r.status})`))
    showCart()
  })
  summary.append(coupon, apply, checkout)
  wrap.append(panel('Cart items', table(['Item', 'Qty', 'Unit', ''], rows)))
  const foot = el('<div class="panel"></div>')
  foot.append(summary)
  wrap.append(foot)
  view.replaceChildren(wrap)
}

async function showPayouts() {
  const res = await call('listPayouts')
  const rows = ((res.json && res.json.items) || []).map((p) => {
    const action = el('<span></span>')
    if (p.status === 'pending') {
      const approve = el('<button class="subtle">Approve</button>')
      approve.addEventListener('click', async () => {
        const r = await call('approvePayout', { pathParams: { [config.params.payoutId || 'payoutId']: p.id } })
        if (r.status >= 300) alert((r.json && r.json.error) || 'Approval rejected')
        showPayouts()
      })
      action.append(approve)
    }
    return [p.id, money(p.amount), p.memo, pill(p.status), action]
  })
  const wrap = el('<div></div>')
  wrap.append(panel('Payouts', table(['Id', 'Amount', 'Memo', 'State', ''], rows)))
  const form = el('<div class="panel form"><div class="row"><label>Amount (cents)<input name="amount" type="number" min="1" /></label><label>Memo<input name="memo" /></label><button class="primary">Request payout</button></div></div>')
  form.querySelector('button').addEventListener('click', async () => {
    const r = await call('createPayout', { body: { amount: Number(form.querySelector('[name=amount]').value), memo: form.querySelector('[name=memo]').value } })
    if (r.status >= 300) alert((r.json && r.json.error) || 'Request failed')
    showPayouts()
  })
  wrap.append(form)
  view.replaceChildren(wrap)
}

async function showInvites() {
  const res = await call('listInvites')
  const rows = ((res.json && res.json.items) || []).map((i) => {
    const action = el('<span></span>')
    if (i.state === 'pending') {
      const down = el('<button class="subtle">Downgrade</button>')
      down.addEventListener('click', async () => {
        await call('downgradeInvite', { pathParams: { [config.params.inviteId || 'inviteId']: i.id }, body: { role: 'viewer' } })
        showInvites()
      })
      action.append(down)
    }
    return [i.email, i.role, pill(i.state), action]
  })
  const wrap = el('<div></div>')
  wrap.append(panel('Invites', table(['Email', 'Role', 'State', ''], rows)))
  const form = el('<div class="panel form"><div class="row"><label>Email<input name="email" type="email" /></label><label>Role<select name="role"><option value="member">member</option><option value="viewer">viewer</option><option value="admin">admin</option></select></label><button class="primary">Invite</button></div></div>')
  form.querySelector('button').addEventListener('click', async () => {
    const r = await call('inviteMember', { body: { email: form.querySelector('[name=email]').value, role: form.querySelector('[name=role]').value } })
    if (r.status >= 300) alert((r.json && r.json.error) || 'Invite failed')
    showInvites()
  })
  wrap.append(form)
  view.replaceChildren(wrap)
}

async function showExports() {
  const res = await call('listExports')
  const rows = ((res.json && res.json.items) || []).map((e) => {
    const action = el('<span></span>')
    if (e.status === 'complete') {
      const dl = el('<button class="subtle">Download</button>')
      dl.addEventListener('click', async () => {
        const r = await call('downloadExport', { pathParams: { [config.params.exportId || 'exportId']: e.id } })
        if (r.status < 300) alert(`Downloaded ${(r.json && r.json.content || '').length} bytes`)
        else alert((r.json && r.json.error) || 'Download rejected')
      })
      action.append(dl)
    }
    return [e.id, e.kind, e.creatorRole, pill(e.status), action]
  })
  const wrap = el('<div></div>')
  wrap.append(panel('Exports', table(['Id', 'Kind', 'Creator role', 'State', ''], rows)))
  const form = el('<div class="panel form"><div class="row"><label>Kind<input name="kind" value="billing" /></label><button class="primary">Queue export</button></div></div>')
  form.querySelector('button').addEventListener('click', async () => {
    const r = await call('queueExport', { body: { kind: form.querySelector('[name=kind]').value } })
    if (r.status >= 300) alert((r.json && r.json.error) || 'Export failed')
    showExports()
  })
  wrap.append(form)
  view.replaceChildren(wrap)
}

async function doLogout() {
  await call('logout', { method: 'POST' })
  csrf = null
  showLogin()
}

async function boot() {
  try {
    await loadConfig()
    logoutBtn.addEventListener('click', doLogout)
    const me = await call('me')
    if (me.status === 200 && me.json && me.json.user) {
      if (me.json.csrfToken) csrf = me.json.csrfToken
      showNav('dashboard')
      await showDashboard()
    } else {
      showLogin()
    }
  } catch (err) {
    view.innerHTML = `<p class="error">Console failed to load.</p>`
  }
}

boot()
