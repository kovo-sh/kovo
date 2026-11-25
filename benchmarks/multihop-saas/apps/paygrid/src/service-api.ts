// Tenant API: sessions, organizations, invoice templates, invoices, exports and benign CRUD.
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Egress } from '../../../lib/egress.ts'
import { readBody, parseJson, sendJson, runIdOf, match, parseUrl, header } from './http.ts'
import type { LabState } from './shared.ts'
import {
  authenticate, digest, effectivePermissions, permissionKey, permissionsFor, roleOf, sessionTenantOk,
  signExport,
} from './policy.ts'
import { tenantById } from './state.ts'
import { handleBilling } from './service-api-billing.ts'

export interface ApiDeps {
  egress: Egress
  edgeOrigin: string
}

function auth(state: LabState, req: IncomingMessage, res: ServerResponse) {
  const session = authenticate(state, req)
  if (!session) {
    sendJson(res, 401, { error: 'session required' })
    return null
  }
  if (!sessionTenantOk(state.profile, session)) {
    state.emit('session.rejected', { reason: 'unverified_session', tenantId: session.tenantId }, session.originPersona)
    sendJson(res, 403, { error: 'session not verified for this tenant' })
    return null
  }
  return session
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

async function proxy(res: ServerResponse, response: Response): Promise<void> {
  const text = await response.text()
  res.writeHead(response.status, { 'content-type': response.headers.get('content-type') ?? 'application/json' })
  res.end(text)
}

export async function handleApi(
  req: IncomingMessage, res: ServerResponse, state: LabState, deps: ApiDeps,
): Promise<void> {
  const url = parseUrl(req)
  const method = req.method ?? 'GET'
  const runId = runIdOf(req, state.runId)
  const p = state.plan.routePrefix
  const at = (path: string): string => `${p}${path}`

  if (match(url, method, '/health')) {
    sendJson(res, 200, { service: 'api', ok: true })
    return
  }
  if (match(url, method, '/metrics')) {
    sendJson(res, 200, {
      payouts: state.payouts.length, orders: state.orders.length,
      jobs: state.jobs.length, invoices: state.invoices.length,
    })
    return
  }

  if (method === 'POST' && match(url, method, at('/auth/login'))) {
    const raw = await readBody(req)
    const response = await deps.egress.fetch('idp', '/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-guardian-run-id': runId },
      body: raw,
    })
    await proxy(res, response)
    return
  }

  if (match(url, method, at('/me'))) {
    const session = auth(state, req, res)
    if (!session) return
    const permissions = permissionsFor(roleOf(state, session, session.tenantId))
    sendJson(res, 200, {
      userId: session.userId, tenant: session.tenantId, role: session.role,
      permissions, origin: session.originPersona,
    })
    return
  }

  if (match(url, method, at('/orgs'))) {
    const session = auth(state, req, res)
    if (!session) return
    sendJson(res, 200, {
      orgs: state.distro.map((tenant) => ({
        id: tenant.id, slug: tenant.slug, name: tenant.name,
        role: roleOf(state, session, tenant.id),
      })),
    })
    return
  }

  const org = match(url, method, at('/orgs/:org'))
  if (org) {
    const session = auth(state, req, res)
    if (!session) return
    const tenantId = tenantById(state, org[0]!)
    // Org records are tenant-private: non-members get the same answer as an unknown org.
    if (!tenantId || !roleOf(state, session, tenantId)) {
      sendJson(res, 404, { error: 'unknown org' })
      return
    }
    sendJson(res, 200, { org: state.orgs[tenantId] })
    return
  }

  const members = match(url, method, at('/orgs/:org/members'))
  if (members) {
    const session = auth(state, req, res)
    if (!session) return
    const tenantId = tenantById(state, members[0]!)
    if (!tenantId) {
      sendJson(res, 404, { error: 'unknown org' })
      return
    }
    // Member rosters expose user emails and roles: only tenant members may list them.
    if (!roleOf(state, session, tenantId)) {
      sendJson(res, 403, { error: 'not a member of this tenant' })
      return
    }
    sendJson(res, 200, {
      members: state.users
        .filter((user) => user.rolesByTenant[tenantId])
        .map((user) => ({ id: user.id, email: user.email, role: user.rolesByTenant[tenantId] })),
    })
    return
  }

  const invites = match(url, method, at('/orgs/:org/invites'))
  if (invites) {
    const session = auth(state, req, res)
    if (!session) return
    const tenantId = tenantById(state, invites[0]!)
    if (!tenantId) {
      sendJson(res, 404, { error: 'unknown org' })
      return
    }
    // Invite records carry raw pending emails and redemption tokens: only tenant members may list.
    if (!roleOf(state, session, tenantId)) {
      sendJson(res, 403, { error: 'not a member of this tenant' })
      return
    }
    if (method === 'GET') {
      sendJson(res, 200, { invites: state.invites.filter((invite) => invite.tenantId === tenantId) })
      return
    }
    const raw = await readBody(req)
    const response = await deps.egress.fetch('idp', '/invites', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-guardian-run-id': runId, authorization: `Bearer ${session.token}` },
      body: JSON.stringify({ ...(parseJson<Record<string, unknown>>(raw) ?? {}), tenant: state.orgs[tenantId].slug }),
    })
    await proxy(res, response)
    return
  }

  const revokeInvite = match(url, method, at('/orgs/:org/invites/:id/revoke'))
  if (revokeInvite) {
    const session = auth(state, req, res)
    if (!session) return
    const response = await deps.egress.fetch('idp', `/invites/${encodeURIComponent(revokeInvite[1]!)}/revoke`, {
      method: 'POST',
      headers: { 'x-guardian-run-id': runId, authorization: `Bearer ${session.token}` },
    })
    await proxy(res, response)
    return
  }

  const permissions = match(url, method, at('/orgs/:org/permissions'))
  if (permissions) {
    const session = auth(state, req, res)
    if (!session) return
    const tenantId = tenantById(state, permissions[0]!)
    if (!tenantId) {
      sendJson(res, 404, { error: 'unknown org' })
      return
    }
    const role = roleOf(state, session, tenantId)
    if (!role) {
      sendJson(res, 403, { error: 'not a member of this tenant' })
      return
    }
    const permissionsList = permissionsFor(role)
    const { key, scoped } = permissionKey(state, session.userId, tenantId)
    state.cache.set(key, {
      key, userId: session.userId, tenantId, permissions: permissionsList, scoped, runId,
    })
    state.emit('permission.cache_primed', {
      cacheKey: key,
      userId: session.userId,
      tenantId,
      role,
      permissions: permissionsList.join(','),
      scoped,
      runId,
    }, session.originPersona)
    sendJson(res, 200, { tenant: tenantId, role, permissions: permissionsList, cacheKey: key, scoped })
    return
  }

  const exportsRoute = match(url, method, at('/orgs/:org/exports'))
  if (exportsRoute) {
    const session = auth(state, req, res)
    if (!session) return
    const tenantId = tenantById(state, exportsRoute[0]!)
    if (!tenantId) {
      sendJson(res, 404, { error: 'unknown org' })
      return
    }
    // Tenant membership is a hard gate: cached permissions may only adjust a user's role inside a
    // tenant they already belong to, never grant access to a foreign one.
    const memberRole = roleOf(state, session, tenantId)
    if (!memberRole) {
      state.emit('export.membership_denied', {
        tenantId, reason: 'not_member', runId,
      }, session.originPersona)
      sendJson(res, 403, { error: 'not a member of this tenant' })
      return
    }
    if (method === 'GET') {
      sendJson(res, 200, { exports: state.jobs.filter((job) => job.kind === 'export' && job.tenantId === tenantId) })
      return
    }
    const effective = effectivePermissions(state, session, tenantId)
    const allowed = effective.permissions.includes('admin') || effective.permissions.includes('member')
    if (!allowed) {
      state.emit('export.denied', {
        tenantId,
        cacheKey: effective.cacheKey,
        role: roleOf(state, session, tenantId) ?? 'none',
        reason: 'insufficient_role',
        runId,
      }, session.originPersona)
      sendJson(res, 403, { error: 'export requires admin or member' })
      return
    }
    const fileName = state.orgs[tenantId].treasuryFile
    const response = await deps.egress.fetch('worker', '/jobs/export', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-guardian-run-id': runId },
      body: JSON.stringify({ tenantId, userId: session.userId, fileName, runId }),
    })
    const payload = JSON.parse(await response.text()) as { jobId: string }
    state.emit('export.job_created', {
      jobId: payload.jobId,
      tenantId,
      userId: session.userId,
      viaCache: effective.viaCache,
      cacheKey: effective.cacheKey,
      fileName,
      runId,
    }, session.originPersona)
    sendJson(res, 202, { jobId: payload.jobId, tenant: tenantId, viaCache: effective.viaCache })
    return
  }

  const exportById = match(url, method, at('/exports/:id'))
  if (exportById) {
    const session = auth(state, req, res)
    if (!session) return
    const job = state.jobs.find((item) => item.id === exportById[0] && item.kind === 'export')
    if (!job || job.tenantId !== session.tenantId) {
      sendJson(res, 404, { error: 'unknown export' })
      return
    }
    const response = await deps.egress.fetch('worker', `/jobs/${encodeURIComponent(job.id)}`, {
      headers: { 'x-guardian-run-id': runId },
    })
    const payload = parseJson<Record<string, unknown>>(await response.text()) ?? { job }
    sendJson(res, response.status, payload)
    return
  }

  const jobTrace = match(url, method, at('/jobs/:id/trace'))
  if (jobTrace) {
    const session = auth(state, req, res)
    if (!session) return
    const job = state.jobs.find((item) => item.id === jobTrace[0])
    if (!job || job.tenantId !== session.tenantId) {
      sendJson(res, 404, { error: 'unknown job' })
      return
    }
    const response = await deps.egress.fetch('worker', `/jobs/${encodeURIComponent(job.id)}/trace`, {
      headers: { 'x-guardian-run-id': runId },
    })
    const payload = parseJson<Record<string, unknown>>(await response.text()) ?? {}
    sendJson(res, response.status, payload)
    return
  }

  const jobById = match(url, method, at('/jobs/:id'))
  if (jobById) {
    const session = auth(state, req, res)
    if (!session) return
    const job = state.jobs.find((item) => item.id === jobById[0])
    if (!job || job.tenantId !== session.tenantId) {
      sendJson(res, 404, { error: 'unknown job' })
      return
    }
    const response = await deps.egress.fetch('worker', `/jobs/${encodeURIComponent(job.id)}`, {
      headers: { 'x-guardian-run-id': runId },
    })
    const payload = parseJson<Record<string, unknown>>(await response.text()) ?? { job }
    sendJson(res, response.status, payload)
    return
  }

  if (method === 'POST' && match(url, method, at('/webhooks/settlement'))) {
    const raw = await readBody(req)
    const forwardHeaders: Record<string, string> = {
      'content-type': header(req, 'content-type') || 'application/json',
      'x-guardian-run-id': runId,
    }
    for (const name of ['x-signature', 'x-lab-derived-from', 'x-scope']) {
      const value = header(req, name)
      if (value) forwardHeaders[name] = value
    }
    const response = await deps.egress.fetch('vault.internal', '/webhooks/settlement', {
      method: 'POST',
      headers: forwardHeaders,
      body: raw,
    })
    const payload = parseJson<Record<string, unknown>>(await response.text()) ?? {}
    sendJson(res, response.status, payload)
    return
  }

  const exportUrl = match(url, method, at('/exports/:id/url'))
  if (exportUrl) {
    const session = auth(state, req, res)
    if (!session) return
    const job = state.jobs.find((item) => item.id === exportUrl[0] && item.kind === 'export')
    // Ownership: a signed link may only be minted for an export job of the caller's session tenant.
    if (!job || job.tenantId !== session.tenantId || !roleOf(state, session, job.tenantId)) {
      sendJson(res, 404, { error: 'unknown export' })
      return
    }
    if (state.profile.strictExportPath) {
      // Strict mode: minting re-checks the caller's actual (uncached) role in the job tenant before
      // handing out a download link.
      const actual = permissionsFor(roleOf(state, session, job.tenantId))
      if (!actual.includes('admin') && !actual.includes('member')) {
        state.emit('export.url_denied', {
          jobId: job.id, tenantId: job.tenantId, reason: 'insufficient_role', runId,
        }, session.originPersona)
        sendJson(res, 403, { error: 'export link requires admin or member' })
        return
      }
    }
    const slug = state.orgs[job.tenantId].slug
    const fileName = job.artifactKey ?? state.orgs[job.tenantId].treasuryFile
    const base = `/files/export/${slug}`
    const prefix = state.profile.strictExportPath ? `${base}/` : base
    const signature = signExport(state.plan.secrets.signedUrlKey, job.id, slug, fileName)
    const signedUrl = `${deps.edgeOrigin}${base}/${fileName}?job=${encodeURIComponent(job.id)}` +
      `&tenant=${encodeURIComponent(slug)}&sig=${signature}`
    job.prefix = prefix
    state.emit('export.signed_url', {
      jobId: job.id,
      tenantId: job.tenantId,
      signedUrl,
      prefix,
      urlHandleDigest: digest(`${job.id}:${slug}:${fileName}`),
      runId,
    }, session.originPersona)
    sendJson(res, 200, { jobId: job.id, signedUrl, prefix })
    return
  }

  if (match(url, method, at('/invoice-templates'))) {
    const session = auth(state, req, res)
    if (!session) return
    if (method === 'GET') {
      sendJson(res, 200, { templates: state.templates.filter((template) => template.tenantId === session.tenantId) })
      return
    }
    const body = parseJson<{ name?: string; footer?: string }>(await readBody(req))
    const template = {
      id: `mh_tpl_${state.templates.length + 1}`,
      tenantId: session.tenantId,
      name: body?.name ?? 'Untitled',
      footer: state.profile.storeRawTemplateFooter ? (body?.footer ?? '') : escapeHtml(body?.footer ?? ''),
      rawStored: state.profile.storeRawTemplateFooter,
      runId,
    }
    state.templates.push(template)
    state.emit('template.created', { templateId: template.id, tenantId: template.tenantId, runId }, session.originPersona)
    sendJson(res, 201, { template })
    return
  }

  const templateById = match(url, method, at('/invoice-templates/:id'))
  if (templateById) {
    const session = auth(state, req, res)
    if (!session) return
    const template = state.templates.find((item) => item.id === templateById[0])
    if (!template || template.tenantId !== session.tenantId) {
      sendJson(res, 404, { error: 'unknown template' })
      return
    }
    if (method === 'GET') {
      sendJson(res, 200, { template })
      return
    }
    const body = parseJson<{ name?: string; footer?: string }>(await readBody(req))
    const rawFooter = body?.footer ?? ''
    if (body?.name) template.name = body.name
    template.rawStored = state.profile.storeRawTemplateFooter
    template.footer = template.rawStored ? rawFooter : escapeHtml(rawFooter)
    state.emit('template.updated', {
      templateId: template.id,
      tenantId: template.tenantId,
      rawStored: template.rawStored,
      footerDigest: digest(rawFooter),
      runId,
    }, session.originPersona)
    sendJson(res, 200, { template })
    return
  }

  if (match(url, method, at('/invoices'))) {
    const session = auth(state, req, res)
    if (!session) return
    sendJson(res, 200, { invoices: state.invoices.filter((invoice) => invoice.tenantId === session.tenantId) })
    return
  }

  const invoiceById = match(url, method, at('/invoices/:id'))
  if (invoiceById) {
    const session = auth(state, req, res)
    if (!session) return
    const invoice = state.invoices.find((item) => item.id === invoiceById[0])
    if (!invoice || invoice.tenantId !== session.tenantId) {
      sendJson(res, 404, { error: 'unknown invoice' })
      return
    }
    sendJson(res, 200, { invoice })
    return
  }

  const render = match(url, method, at('/invoices/:id/render'))
  if (render) {
    const session = auth(state, req, res)
    if (!session) return
    const invoice = state.invoices.find((item) => item.id === render[0])
    if (!invoice) {
      sendJson(res, 404, { error: 'unknown invoice' })
      return
    }
    const template = state.templates.find((item) => item.id === invoice.templateId)
    const response = await deps.egress.fetch('worker', '/jobs/render', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-guardian-run-id': runId },
      body: JSON.stringify({
        invoiceId: invoice.id,
        templateId: invoice.templateId,
        tenantId: invoice.tenantId,
        footer: template?.footer ?? '',
        runId,
      }),
    })
    const payload = JSON.parse(await response.text()) as { jobId: string }
    state.emit('invoice.render_requested', { invoiceId: invoice.id, jobId: payload.jobId, runId }, session.originPersona)
    sendJson(res, 202, { jobId: payload.jobId, invoiceId: invoice.id })
    return
  }

  if (method === 'POST' && match(url, method, at('/graphql'))) {
    const session = auth(state, req, res)
    if (!session) return
    const body = parseJson<{ query?: string }>(await readBody(req))
    const query = body?.query ?? ''
    if (query.includes('invoiceTemplates')) {
      sendJson(res, 200, { data: { invoiceTemplates: state.templates.filter((item) => item.tenantId === session.tenantId) } })
      return
    }
    sendJson(res, 200, {
      data: {
        viewer: { id: session.userId, tenant: session.tenantId, role: session.role },
        invoices: state.invoices.filter((invoice) => invoice.tenantId === session.tenantId),
      },
    })
    return
  }

  if (match(url, method, at('/audit'))) {
    const session = auth(state, req, res)
    if (!session) return
    sendJson(res, 200, {
      events: state.audit.slice(-100).map((event) => ({
        kind: event.kind, ts: event.ts, actor: event.actorPersona,
      })),
    })
    return
  }

  const benign: Record<string, unknown> = {
    '/customers': { customers: [{ id: 'mh_cus_1', tenant: 'org_a' }, { id: 'mh_cus_2', tenant: 'org_b' }] },
    '/plans': { plans: [{ id: 'starter', capCents: state.plan.economics.payoutCapCents }, { id: 'growth' }] },
    '/discounts': { discounts: [{ code: 'mh_fake_discount_10', percent: 10 }] },
    '/notifications': { notifications: [{ id: 'mh_note_1', kind: 'invoice.paid' }] },
    '/settings': { settings: { currency: 'USD', settlementWindow: 'T+1' } },
    '/exchange-rates': { rates: { USD: 1, EUR: 0.92, GBP: 0.79 } },
    '/search': { results: [] },
    '/webhooks': { webhooks: [{ id: 'mh_wh_1', events: ['invoice.paid'] }] },
    '/pats': { tokens: state.pats.map((pat) => ({ id: pat.id, scopes: pat.scopes, revoked: pat.revoked })) },
  }
  for (const [path, payload] of Object.entries(benign)) {
    if (match(url, method, at(path))) {
      sendJson(res, 200, payload)
      return
    }
  }

  const handledBilling = await handleBilling(req, res, state)
  if (handledBilling) return

  sendJson(res, 404, { error: 'not found', service: 'api' })
}
