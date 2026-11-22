// View renderers. Project descriptions are stored as rich HTML and rendered with innerHTML so teams
// can format their workspace notes.
export function el(html) {
  const t = document.createElement('template')
  t.innerHTML = html.trim()
  return t.content.firstElementChild
}

export function loginView(onSubmit) {
  const node = el(`
    <form class="card login">
      <h1>Sign in</h1>
      <label>Email <input name="email" type="email" autocomplete="username" /></label>
      <label>Password <input name="password" type="password" autocomplete="current-password" /></label>
      <button type="submit">Continue</button>
      <p class="error" hidden></p>
    </form>`)
  node.addEventListener('submit', (e) => {
    e.preventDefault()
    onSubmit(node.email.value, node.password.value, node.querySelector('.error'))
  })
  return node
}

export function dashboardView(data) {
  const node = el(`<div class="dash"></div>`)
  node.append(statCard('Projects', data.projects.length))
  node.append(statCard('Open invoices', data.invoices.filter((i) => i.status === 'open').length))
  node.append(statCard('Members', data.members.length))
  const list = el(`<section class="panel"><h2>Workspaces</h2><div class="rows"></div></section>`)
  const rows = list.querySelector('.rows')
  for (const p of data.projects) {
    const row = el(`<article class="project"><h3></h3><div class="desc"></div></article>`)
    row.querySelector('h3').textContent = p.name
    row.querySelector('.desc').innerHTML = p.description || ''
    rows.append(row)
  }
  node.append(list)
  node.append(invoicePanel(data.invoices))
  return node
}

function invoicePanel(invoices) {
  const panel = el(`<section class="panel"><h2>Invoices</h2><table><tbody></tbody></table></section>`)
  const tbody = panel.querySelector('tbody')
  for (const inv of invoices) {
    const tr = el('<tr><td class="num"></td><td class="amt"></td><td class="st"></td></tr>')
    tr.querySelector('.num').textContent = inv.number
    tr.querySelector('.amt').textContent = `$${(inv.amount / 100).toFixed(2)}`
    tr.querySelector('.st').textContent = inv.status
    tbody.append(tr)
  }
  return panel
}

function statCard(label, value) {
  const c = el(`<div class="stat"><span class="value"></span><span class="label"></span></div>`)
  c.querySelector('.value').textContent = String(value)
  c.querySelector('.label').textContent = label
  return c
}

export function navView(tabs, onSelect) {
  const nav = el('<nav class="nav"></nav>')
  for (const tab of tabs) {
    const b = el('<button class="tab"></button>')
    b.textContent = tab
    b.addEventListener('click', () => onSelect(tab))
    nav.append(b)
  }
  return nav
}
