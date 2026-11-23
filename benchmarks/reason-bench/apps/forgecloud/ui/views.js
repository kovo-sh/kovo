// View renderers. All dynamic text is inserted with textContent; user-controlled strings are never
// parsed as markup.
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

export function navView(labels, onSelect) {
  const nav = el('<nav class="nav"></nav>')
  for (const [key, label] of Object.entries(labels)) {
    const b = el('<button class="tab"></button>')
    b.textContent = label
    b.dataset.tab = key
    b.addEventListener('click', () => onSelect(key))
    nav.append(b)
  }
  return nav
}

export function panel(title) {
  const node = el('<section class="panel"><h2></h2><div class="body"></div></section>')
  node.querySelector('h2').textContent = title
  return node
}

export function table(headers, rows) {
  const node = el('<table><thead></thead><tbody></tbody></table>')
  const head = el('<tr></tr>')
  for (const h of headers) {
    const th = document.createElement('th')
    th.textContent = h
    head.append(th)
  }
  node.querySelector('thead').append(head)
  const tbody = node.querySelector('tbody')
  for (const row of rows) {
    const tr = el('<tr></tr>')
    for (const cell of row) {
      const td = document.createElement('td')
      if (cell instanceof Node) td.append(cell)
      else td.textContent = String(cell ?? '')
      tr.append(td)
    }
    tbody.append(tr)
  }
  return node
}

export function button(label, onClick, cls = '') {
  const b = el(`<button class="${cls}"></button>`)
  b.textContent = label
  b.addEventListener('click', onClick)
  return b
}

export function projectsView(items, onCreate) {
  const p = panel('Projects')
  const body = p.querySelector('.body')
  body.append(table(['Name', 'Visibility', 'State'], items.map((it) => [it.name, it.visibility, it.state])))
  const form = el(`
    <form class="inline">
      <input name="name" placeholder="new project" />
      <button type="submit">Create</button>
    </form>`)
  form.addEventListener('submit', (e) => { e.preventDefault(); onCreate(form.name.value) })
  body.append(form)
  return p
}

export function pipelinesView(items) {
  const p = panel('Pipelines')
  p.querySelector('.body').append(table(['Name', 'Project', 'State', 'Visibility'],
    items.map((it) => [it.name, it.project, it.state, it.visibility])))
  return p
}

export function buildsView(items, onSelect) {
  const p = panel('Builds')
  const body = p.querySelector('.body')
  body.append(table(['Run', 'State', 'Commit'], items.map((it) => [
    button(`#${it.number}`, () => onSelect(it), 'link'), it.state, it.commit,
  ])))
  return p
}

export function logPanel() {
  const p = panel('Live build log')
  const pre = el('<pre class="log" aria-live="polite"></pre>')
  p.querySelector('.body').append(pre)
  p.dataset.lines = '0'
  p.appendLine = (line) => {
    pre.textContent += `${line}\n`
    p.dataset.lines = String(Number(p.dataset.lines) + 1)
  }
  p.reset = () => { pre.textContent = ''; p.dataset.lines = '0' }
  return p
}

export function secretsView(items, handlers) {
  const p = panel('Secrets')
  const body = p.querySelector('.body')
  const selected = new Set()
  const rows = items.map((it) => {
    const box = el('<input type="checkbox" />')
    box.addEventListener('change', () => { box.checked ? selected.add(it.id) : selected.delete(it.id) })
    return [box, it.name, it.kind, it.value, button('Delete', () => handlers.onDelete(it.id), 'link danger')]
  })
  body.append(table(['', 'Name', 'Kind', 'Value', ''], rows))
  const form = el(`
    <form class="inline">
      <input name="name" placeholder="secret name" />
      <input name="value" placeholder="value (generated if empty)" />
      <button type="submit">Add secret</button>
    </form>`)
  form.addEventListener('submit', (e) => {
    e.preventDefault()
    handlers.onCreate(form.name.value, form.value.value)
  })
  body.append(form)
  body.append(button('Rotate selected (batch)', () => handlers.onBatch([...selected]), 'secondary'))
  return p
}

export function deploymentsView(items, handlers) {
  const p = panel('Deployments')
  const rows = items.map((it) => [
    it.version, it.env, it.state, it.approval,
    `${it.autoRelease ? 'armed ' : ''}${it.scheduledAt ? new Date(Number(it.scheduledAt)).toLocaleString() : ''}`,
    button('Approve', () => handlers.onApprove(it.id), 'link'),
    button('Schedule', () => handlers.onSchedule(it.id), 'link'),
    button('Dispute', () => handlers.onDispute(it.id), 'link'),
    button('Release', () => handlers.onRelease(it.id), 'link'),
  ])
  p.querySelector('.body').append(table(['Version', 'Env', 'State', 'Approval', 'Trigger', '', '', '', ''], rows))
  return p
}

export function webhooksView(items, handlers) {
  const p = panel('Webhooks')
  const body = p.querySelector('.body')
  body.append(table(['Endpoint', 'Events', 'Active', ''], items.map((it) => [
    it.url, it.events, it.active ? 'yes' : 'no', button('Deliveries', () => handlers.onDeliveries(it.id), 'link'),
  ])))
  const form = el(`
    <form class="inline">
      <input name="url" placeholder="https://example.test/hook" />
      <input name="events" placeholder="build.completed" />
      <button type="submit">Add webhook</button>
    </form>`)
  form.addEventListener('submit', (e) => {
    e.preventDefault()
    handlers.onCreate(form.url.value, form.events.value)
  })
  body.append(form)
  return p
}

export function membersView(items, handlers) {
  const p = panel('Members')
  const body = p.querySelector('.body')
  body.append(table(['Name', 'Email', 'Role'], items.map((it) => [it.name, it.email, it.role])))
  const form = el(`
    <form class="inline">
      <input name="email" placeholder="teammate@example.test" />
      <input name="role" placeholder="developer" />
      <button type="submit">Invite</button>
    </form>`)
  form.addEventListener('submit', (e) => {
    e.preventDefault()
    handlers.onInvite(form.email.value, form.role.value)
  })
  body.append(form)
  return p
}

export function searchView(onSearch, onFacets) {
  const p = panel('Search')
  const body = p.querySelector('.body')
  const form = el(`
    <form class="inline">
      <input name="q" placeholder="find projects, pipelines, secrets" />
      <button type="submit">Search</button>
      <button type="button" class="secondary" data-facets>Facet counts</button>
    </form>`)
  form.addEventListener('submit', (e) => { e.preventDefault(); onSearch(form.q.value) })
  form.querySelector('[data-facets]').addEventListener('click', () => onFacets(form.q.value))
  const out = el('<div class="results"></div>')
  body.append(form, out)
  p.renderResults = (items) => {
    out.replaceChildren(table(['Type', 'Name', 'Project'], items.map((it) => [it.type, it.name, it.project])))
  }
  p.renderFacets = (facets) => {
    out.replaceChildren(table(['Bucket', 'Count'], (facets.facets || []).map((f) => [f.bucket, f.count])))
  }
  return p
}

export function statusLine(text, isError = false) {
  const node = el(`<p class="${isError ? 'error' : 'hint'}"></p>`)
  node.textContent = text
  return node
}
