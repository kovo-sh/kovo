// Collaboration surface: comments / activity feed, members directory form, notification previews, account page.
import { csrfValid, issueCsrf } from './csrf.mjs'
import { escapeHtml, sendHtml, sendJson } from './http-util.mjs'
import { marker } from './markers.mjs'
import { renderTemplate, renderTemplateSafe, TemplateError } from './template.mjs'

const page = (title, inner) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${escapeHtml(title)} - Orbit Workspace</title></head>
<body><h1>${escapeHtml(title)}</h1>${inner}</body></html>`

export function register(router, ctx) {
  // ---- comments (hos-15: stored here, rendered unescaped on the activity page => second-order XSS) -------
  router.post('/api/v1/comments', async c => {
    const user = c.requireUser()
    if (!user) return
    const body = await c.json()
    const project = ctx.s.projects.get(String(body.projectId ?? ''))
    if (!project || project.tenantId !== user.tenant) return sendJson(c.res, 404, { error: 'project_not_found' })
    const text = String(body.body ?? '').slice(0, 2000)
    if (!text) return sendJson(c.res, 400, { error: 'body_required' })
    const comment = { id: `c_${++ctx.s.counters.comment}`, projectId: project.id, author: user.userId, body: text }
    ctx.s.comments.push(comment)
    sendJson(c.res, 201, { id: comment.id, projectId: comment.projectId })
  })

  router.get('/api/v1/comments', c => {
    const user = c.requireUser()
    if (!user) return
    const project = ctx.s.projects.get(String(c.query.projectId ?? ''))
    if (!project || project.tenantId !== user.tenant) return sendJson(c.res, 404, { error: 'project_not_found' })
    sendJson(c.res, 200, { comments: ctx.s.comments.filter(x => x.projectId === project.id) })
  })

  router.get('/app/projects/:id/activity', c => {
    const user = c.requireUser()
    if (!user) return
    const project = ctx.s.projects.get(c.params.id)
    if (!project || project.tenantId !== user.tenant) return sendJson(c.res, 404, { error: 'project_not_found' })
    const items = ctx.s.comments
      .filter(x => x.projectId === project.id)
      .map(x => `<li class="comment" data-author="${escapeHtml(x.author)}">${ctx.fixed('hos-15') ? escapeHtml(x.body) : x.body}</li>`)
      .join('')
    sendHtml(c.res, 200, page(`Activity - ${project.name}`, `<ul id="activity">${items}</ul>`))
  })

  // ---- members directory (hos-07: CSRF-protected form whose field is concatenated into SQL) ---------------
  router.get('/app/members', c => {
    const token = issueCsrf(ctx, c.res)
    sendHtml(c.res, 200, page('Members', `<form action="/app/members/search" method="post">
<input type="hidden" name="_csrf" value="${token}">
<input type="text" name="member_id">
<button type="submit">Find</button>
</form>`))
  })

  router.post('/app/members/search', async c => {
    const form = new URLSearchParams(await c.text())
    if (!csrfValid(ctx, c.req, form.get('_csrf'))) return sendJson(c.res, 403, { error: 'invalid_csrf_token' })
    const user = c.requireUser()
    if (!user) return
    const memberId = form.get('member_id') ?? ''
    try {
      const rows = ctx.fixed('hos-07')
        ? ctx.s.db.prepare('SELECT id, name, email FROM members WHERE tenant_id = ? AND id = ?').all(user.tenant, memberId)
        : ctx.s.db.prepare(`SELECT id, name, email FROM members WHERE tenant_id = '${user.tenant}' AND id = '${memberId}'`).all()
      const body = rows.length
        ? `<table id="members">${rows.map(r => `<tr><td>${escapeHtml(r.id)}</td><td>${escapeHtml(r.name)}</td><td>${escapeHtml(r.email)}</td></tr>`).join('')}</table>`
        : '<p class="empty">No members matched.</p>'
      sendHtml(c.res, 200, page('Members', body))
    } catch (err) {
      sendHtml(c.res, 500, page('Members', `<pre>${escapeHtml(String(err?.message ?? err))}</pre>`))
    }
  })

  // ---- notification preview (hos-19: user template text reaches an expression evaluator => SSTI) ---------
  router.post('/api/v1/notifications/preview', async c => {
    const user = c.requireUser()
    if (!user) return
    const body = await c.json()
    const tenant = ctx.s.tenants.get(user.tenant)
    const vars = {
      name: String(body.name ?? ctx.s.users.get(user.userId)?.displayName ?? 'there'),
      company: tenant?.name ?? '',
      plan: tenant?.plan ?? '',
      deployToken: marker('hos-19'),
    }
    try {
      const rendered = ctx.fixed('hos-19')
        ? renderTemplateSafe(String(body.template ?? ''), vars, ['name', 'company', 'plan'])
        : renderTemplate(String(body.template ?? ''), vars)
      sendJson(c.res, 200, { rendered })
    } catch (err) {
      if (err instanceof TemplateError) return sendJson(c.res, 400, { error: 'template_error', message: err.message })
      throw err
    }
  })

  // ---- account page (hos-17: path-info wildcard + identity-blind edge cache => web cache deception) -------
  const accountHandler = c => {
    const user = c.requireUser()
    if (!user) return
    const splat = c.params.splat ?? ''
    if (ctx.fixed('hos-17') && splat !== 'profile') return sendJson(c.res, 404, { error: 'not_found' })
    const stored = ctx.s.users.get(user.userId)
    const tenant = ctx.s.tenants.get(user.tenant)
    const html = page('Account', `<dl>
<dt>Email</dt><dd>${escapeHtml(stored?.email ?? user.email)}</dd>
<dt>Organisation</dt><dd>${escapeHtml(tenant?.name ?? '')}</dd>
<dt>Plan</dt><dd>${escapeHtml(tenant?.plan ?? '')}</dd>
<dt>API key hint</dt><dd>${escapeHtml(marker('hos-17'))}</dd>
</dl>`)
    sendHtml(c.res, 200, html, { 'cache-control': ctx.fixed('hos-17') ? 'private, no-store' : 'public, max-age=300' })
  }
  router.get('/app/account', c => accountHandler({ ...c, params: { splat: 'profile' }, requireUser: c.requireUser, res: c.res }))
  router.get('/app/account/*', accountHandler)
}
