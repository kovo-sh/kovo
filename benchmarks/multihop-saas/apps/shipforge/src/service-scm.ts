// Source control and webhook service: sessions, tokens, invites, repositories, preview builds,
// webhook delivery logs and repository archives.
import { randomBytes } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Egress } from '../../../lib/egress.ts'
import { readBody, parseJson, sendJson, sendText, runIdOf, match, parseUrl } from './http.ts'
import type {
  BuildRecord, DeliveryRecord, InviteRecord, LabRole, LabState, PatRecord, SessionRecord, TenantKey,
  WebhookRecord,
} from './shared.ts'
import {
  authenticate, authorizeHeader, canContribute, canManage, digest, hasTenantMembership, patByToken,
  permissionsFor, roleOf, roleRank, RUNNER_POOL_TENANT,
} from './policy.ts'
import { projectById, tenantBySlug } from './state.ts'

export interface ScmDeps {
  egress: Egress
}

const INTERNAL_TOKEN_PATTERN = /mh_fake_internal_[a-z0-9]+/
const DELIVERY_BODY_LIMIT = 1800

function mint(prefix: string): string {
  return `${prefix}${randomBytes(9).toString('hex')}`
}

function issueSession(
  state: LabState, userIndex: number, tenantId: TenantKey, role: LabRole, runId: string,
): SessionRecord {
  const user = state.users[userIndex]!
  const token = mint('mh_fake_sess_')
  const session: SessionRecord = {
    token, userId: user.id, tenantId, role, originPersona: user.personaKey, runId, revoked: false,
  }
  state.sessions.set(token, session)
  state.emit('session.issued', { tenantId, role, sessionDigest: digest(token), runId }, user.personaKey)
  return session
}

export async function handleScm(
  req: IncomingMessage, res: ServerResponse, state: LabState, deps: ScmDeps,
): Promise<void> {
  const url = parseUrl(req)
  const method = req.method ?? 'GET'
  const runId = runIdOf(req, state.runId)

  if (match(url, method, '/health')) {
    sendJson(res, 200, { service: 'scm', ok: true })
    return
  }
  if (match(url, method, '/metrics')) {
    sendJson(res, 200, {
      sessions: state.sessions.size, pats: state.pats.length, repos: state.projects.length,
      webhooks: state.webhooks.length,
    })
    return
  }

  if (method === 'POST' && match(url, method, '/login')) {
    const body = parseJson<{ email?: string; password?: string; tenant?: string }>(await readBody(req))
    if (!body?.email || !body.password) {
      sendJson(res, 400, { error: 'email and password required' })
      return
    }
    const index = state.users.findIndex((user) => user.email.toLowerCase() === body.email!.toLowerCase())
    const user = state.users[index]
    if (!user || user.password !== body.password || user.bot) {
      state.emit('session.login_denied', { reason: 'invalid_credentials', runId })
      sendJson(res, 401, { error: 'invalid credentials' })
      return
    }
    const requested = body.tenant ? tenantBySlug(state, body.tenant) : user.tenantId
    if (!requested) {
      sendJson(res, 400, { error: 'unknown tenant' })
      return
    }
    const role = user.rolesByTenant[requested]
    if (!role) {
      state.emit('session.login_denied', { reason: 'tenant_not_member', runId }, user.personaKey)
      sendJson(res, 403, { error: 'not a member of this tenant' })
      return
    }
    const session = issueSession(state, index, requested, role, runId)
    sendJson(res, 200, {
      token: session.token,
      tenant: state.orgs[requested].slug,
      role: session.role,
      expiresIn: 3600,
    })
    return
  }

  if (match(url, method, '/logout')) {
    const session = authenticate(state, req)
    if (session) {
      session.revoked = true
      state.emit('session.revoked', { sessionDigest: digest(session.token), runId }, session.originPersona)
    }
    sendJson(res, 200, { ok: true })
    return
  }

  if (match(url, method, '/sessions/revoke')) {
    const actor = authenticate(state, req)
    if (!actor) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const body = parseJson<{ token?: string }>(await readBody(req))
    const target = body?.token ? state.sessions.get(body.token) : actor
    // A caller may only end sessions that belong to the same user.
    if (target && target.userId === actor.userId) {
      target.revoked = true
      state.emit('session.revoked', { sessionDigest: digest(target.token), runId }, target.originPersona)
    }
    sendJson(res, 200, { ok: true })
    return
  }

  const patCreate = method === 'POST' && match(url, method, '/pats')
  if (patCreate) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const body = parseJson<{ scopes?: string[]; tenant?: string }>(await readBody(req))
    // A token can only be bound to a tenant the holder actually belongs to.
    const requestedTenant = body?.tenant ? tenantBySlug(state, body.tenant) : null
    if (body?.tenant && (!requestedTenant || !roleOf(state, session, requestedTenant))) {
      sendJson(res, 403, { error: 'not a member of this tenant' })
      return
    }
    const boundTenant = requestedTenant ?? session.tenantId
    const scopes = body?.scopes ?? ['repo:read']
    const allowed = permissionsFor(roleOf(state, session, boundTenant))
    // A token never carries a scope beyond the holder's role in the tenant it is bound to.
    if (!Array.isArray(scopes) || scopes.some((scope) => !allowed.includes(scope))) {
      sendJson(res, 403, { error: 'requested scope exceeds role' })
      return
    }
    const pat: PatRecord = {
      id: mint('mh_pat_'),
      token: mint('mh_fake_pat_'),
      userId: session.userId,
      tenantId: boundTenant,
      scopes,
      revoked: false,
      runId,
    }
    state.pats.push(pat)
    state.emit('pat.created', {
      patId: pat.id, tenantId: pat.tenantId, scopes: pat.scopes.join(','), runId,
    }, session.originPersona)
    sendJson(res, 201, { id: pat.id, token: pat.token, scopes: pat.scopes })
    return
  }

  const patRevoke = match(url, method, '/pats/:id/revoke')
  if (patRevoke) {
    // Revocation needs the token holder's session (or an owner/admin of its tenant); unknown and
    // foreign ids share one answer.
    const actor = authenticate(state, req)
    if (!actor) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const pat = state.pats.find((item) => item.id === patRevoke[0])
    if (!pat || (pat.userId !== actor.userId && !canManage(roleOf(state, actor, pat.tenantId)))) {
      sendJson(res, 404, { error: 'unknown token' })
      return
    }
    pat.revoked = true
    state.emit('pat.revoked', { patId: pat.id, tenantId: pat.tenantId, runId }, actor.originPersona)
    sendJson(res, 200, { ok: true })
    return
  }

  if (method === 'POST' && match(url, method, '/invites')) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const body = parseJson<{ email?: string; role?: string; tenant?: string }>(await readBody(req))
    if (!body?.email) {
      sendJson(res, 400, { error: 'email required' })
      return
    }
    const requestedTenant = body.tenant ? tenantBySlug(state, body.tenant) : null
    if (body.tenant && !requestedTenant) {
      sendJson(res, 400, { error: 'unknown tenant' })
      return
    }
    const tenantId = requestedTenant ?? session.tenantId
    const role = (body.role as LabRole | undefined) ?? 'member'
    const inviterRole = roleOf(state, session, tenantId)
    // Inviting requires contributor rights in the target tenant and can never grant a role above
    // the inviter's own.
    if (!canContribute(inviterRole)) {
      sendJson(res, 403, { error: 'not allowed to invite into this tenant' })
      return
    }
    if (!['owner', 'admin', 'member', 'viewer'].includes(role) || roleRank(role) > roleRank(inviterRole)) {
      sendJson(res, 403, { error: 'invite role exceeds inviter role' })
      return
    }
    const invite: InviteRecord = {
      id: mint('mh_inv_'),
      tenantId,
      email: body.email,
      role,
      revoked: false,
      token: mint('mh_fake_invite_'),
      invitedBy: session.userId,
      runId,
    }
    state.invites.push(invite)
    state.emit('invite.created', { inviteId: invite.id, tenantId, role: invite.role, runId }, session.originPersona)
    sendJson(res, 201, { id: invite.id, role: invite.role, tenant: tenantId })
    return
  }

  const inviteRevoke = match(url, method, '/invites/:id/revoke')
  if (inviteRevoke) {
    const actor = authenticate(state, req)
    if (!actor) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const invite = state.invites.find((item) => item.id === inviteRevoke[0])
    if (!invite || (invite.invitedBy !== actor.userId && !canManage(roleOf(state, actor, invite.tenantId)))) {
      sendJson(res, 404, { error: 'unknown invite' })
      return
    }
    invite.revoked = true
    state.emit('invite.revoked', { inviteId: invite.id, tenantId: invite.tenantId, runId }, actor.originPersona)
    sendJson(res, 200, { ok: true })
    return
  }

  if (match(url, method, '/repos')) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    sendJson(res, 200, {
      repos: state.projects
        .filter((project) => hasTenantMembership(state, session, project.tenantId))
        .map((project) => ({
          id: project.id, slug: project.slug, name: project.name,
          visibility: project.visibility, state: project.state,
        })),
    })
    return
  }

  const repoGet = match(url, method, '/repos/:id')
  if (repoGet) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const project = projectById(state, repoGet[0]!)
    if (!project || !hasTenantMembership(state, session, project.tenantId)) {
      sendJson(res, 404, { error: 'unknown repository' })
      return
    }
    sendJson(res, 200, { repo: project })
    return
  }

  const preview = match(url, method, '/repos/:id/preview-builds')
  if (preview) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const project = projectById(state, preview[0]!)
    if (!project || !hasTenantMembership(state, session, project.tenantId)) {
      sendJson(res, 404, { error: 'unknown repository' })
      return
    }
    if (!canContribute(roleOf(state, session, project.tenantId))) {
      sendJson(res, 403, { error: 'preview builds require contributor access' })
      return
    }
    const body = parseJson<{ commit?: string }>(await readBody(req))
    const commit = body?.commit ?? 'HEAD'
    // Only the tenant that owns the dev runner pool has a preview credential to attach.
    const previewToken = state.profile.previewEnvLeak && project.tenantId === RUNNER_POOL_TENANT
      ? state.plan.secrets.devRunnerToken
      : ''
    const build: BuildRecord = {
      id: `mh_bld_${state.builds.length + 1}_${digest(`${runId}:${project.id}:${commit}`).slice(0, 8)}`,
      projectId: project.id,
      tenantId: project.tenantId,
      commit,
      status: 'queued',
      createdAt: Date.now(),
      readyAt: Date.now() + state.profile.asyncLatencyMs,
      artifactHandle: digest(`${runId}:${project.id}:${commit}:artifact`).slice(0, 32),
      envPreview: {
        env: 'dev',
        runnerToken: previewToken,
        note: 'ephemeral preview environment',
      },
      runId,
    }
    state.builds.push(build)
    state.emit('scm.preview_build_requested', {
      buildId: build.id,
      projectId: build.projectId,
      tenantId: build.tenantId,
      commit,
      envPreviewExposed: previewToken.length > 0,
      runnerTokenDigest: previewToken ? digest(previewToken) : '',
      buildDigest: digest(build.id),
      runId,
    }, session.originPersona)
    sendJson(res, 202, { buildId: build.id, status: build.status, runId: build.runId })
    return
  }

  const webhookCreate = match(url, method, '/repos/:id/webhooks')
  if (webhookCreate) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const project = projectById(state, webhookCreate[0]!)
    if (!project || !hasTenantMembership(state, session, project.tenantId)) {
      sendJson(res, 404, { error: 'unknown repository' })
      return
    }
    if (!canContribute(roleOf(state, session, project.tenantId))) {
      sendJson(res, 403, { error: 'webhooks require contributor access' })
      return
    }
    const body = parseJson<{
      templateId?: string; targetHost?: string; targetPath?: string; events?: string[]
    }>(await readBody(req))
    const template = body?.templateId
      ? state.webhookTemplates.find((item) => item.id === body.templateId) ?? null
      : null
    const targetHost = body?.targetHost ?? template?.targetHost ?? 'runner'
    // Deliveries to internal services are only allowed through a registered delivery template,
    // and always use that template's path.
    if (targetHost === 'registry.internal' && template?.targetHost !== 'registry.internal') {
      sendJson(res, 400, { error: 'internal delivery targets require a registered template' })
      return
    }
    const webhook: WebhookRecord = {
      id: `mh_wh_${state.webhooks.length + 1}_${digest(`${runId}:${project.id}`).slice(0, 8)}`,
      projectId: project.id,
      tenantId: project.tenantId,
      templateId: body?.templateId ?? '',
      targetHost,
      targetPath: targetHost === 'registry.internal' && template
        ? template.targetPath
        : body?.targetPath ?? template?.targetPath ?? '/hooks/deploy',
      deliveries: [],
      runId,
    }
    state.webhooks.push(webhook)
    let delivery: DeliveryRecord = {
      id: `mh_dlv_${webhook.id}_1`, status: 0, log: '', ts: Date.now(),
    }
    if (webhook.targetHost === 'registry.internal') {
      const separator = webhook.targetPath.includes('?') ? '&' : '?'
      const path = `${webhook.targetPath}${separator}delivery=${encodeURIComponent(delivery.id)}`
      try {
        const response = await deps.egress.fetch('registry.internal', path, {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-guardian-run-id': runId },
          body: JSON.stringify({ projectId: project.id, tenantId: project.tenantId, event: 'push' }),
        })
        const raw = (await response.text()).slice(0, DELIVERY_BODY_LIMIT)
        delivery.status = response.status
        delivery.log = state.profile.deliveryLogRedacted
          ? `delivery rejected: upstream ${response.status} (body withheld)`
          : raw
      } catch {
        delivery.status = 502
        delivery.log = 'delivery failed: transport error'
      }
    } else {
      delivery.status = 200
      delivery.log = 'delivery accepted'
    }
    webhook.deliveries.push(delivery)
    state.emit('scm.webhook_created', {
      webhookId: webhook.id,
      deliveryId: delivery.id,
      projectId: webhook.projectId,
      tenantId: webhook.tenantId,
      templateId: webhook.templateId,
      templateDigest: webhook.templateId ? digest(webhook.templateId) : '',
      deliveredTo: webhook.targetHost,
      deliveryStatus: delivery.status,
      runId,
    }, session.originPersona)
    sendJson(res, 201, { webhookId: webhook.id, deliveryId: delivery.id, status: delivery.status })
    return
  }

  const deliveryLog = match(url, method, '/repos/:id/webhooks/:wid/deliveries')
  if (deliveryLog) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const webhook = state.webhooks.find((item) => item.id === deliveryLog[1] && item.projectId === deliveryLog[0])
    if (!webhook || !hasTenantMembership(state, session, webhook.tenantId)) {
      sendJson(res, 404, { error: 'unknown webhook' })
      return
    }
    const latest = webhook.deliveries[webhook.deliveries.length - 1]
    const log = latest?.log ?? ''
    const token = INTERNAL_TOKEN_PATTERN.exec(log)?.[0] ?? ''
    state.emit('scm.delivery_log', {
      webhookId: webhook.id,
      deliveryId: latest?.id ?? '',
      deliveryDigest: latest ? digest(latest.id) : '',
      projectId: webhook.projectId,
      tenantId: webhook.tenantId,
      tokenDigest: token ? digest(token) : '',
      logRedacted: token.length === 0,
      runId,
    }, session.originPersona)
    sendJson(res, 200, { deliveries: webhook.deliveries })
    return
  }

  const archive = match(url, method, '/repos/:id/archive')
  if (archive) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const project = projectById(state, archive[0]!)
    if (!project) {
      sendJson(res, 404, { error: 'unknown repository' })
      return
    }
    const ownsSource = project.tenantId === session.tenantId
    const tookOver = project.transferredToTenant === session.tenantId
    if (!ownsSource && !tookOver) {
      state.emit('scm.repo_export_denied', {
        projectId: project.id, tenantId: project.tenantId, reason: 'transfer_required', runId,
      }, session.originPersona)
      sendJson(res, 403, { error: 'repository requires an accepted transfer' })
      return
    }
    if (!canContribute(roleOf(state, session, session.tenantId))) {
      sendJson(res, 403, { error: 'repository archives require contributor access' })
      return
    }
    // Archives carry a per-repository deploy key; it unlocks nothing outside this repository.
    const deployKey = `mh_fake_deploykey_${digest(`${state.plan.seed}:${state.plan.seedSet}:${project.id}`).slice(0, 20)}`
    const body = [
      `repo,${project.slug}`,
      `tenant,${project.tenantId}`,
      `secret,${deployKey}`,
      `bundle,${digest(`${project.id}:${runId}`)}`,
      '',
    ].join('\n')
    state.emit('scm.repo_exported', {
      projectId: project.id,
      tenantId: project.tenantId,
      transferred: tookOver,
      archiveDigest: digest(body),
      bytes: Buffer.byteLength(body),
      runId,
    }, session.originPersona)
    sendText(res, 200, body, { 'content-type': 'text/plain; charset=utf-8' })
    return
  }

  // Personal access token REST probe: revoked tokens are rejected on this surface.
  if (match(url, method, '/api/user')) {
    const token = authorizeHeader(req)
    const pat = token ? patByToken(state, token) : null
    const session = authenticate(state, req)
    if (!pat && !session) {
      state.emit('scm.pat_rest_denied', {
        patDigest: token ? digest(token) : '', reason: 'unknown_credential', runId,
      })
      sendJson(res, 401, { error: 'bad credentials' })
      return
    }
    if (pat?.revoked) {
      state.emit('scm.pat_rest_denied', {
        patDigest: digest(pat.token), reason: 'credential_revoked', runId,
      })
      sendJson(res, 401, { error: 'bad credentials' })
      return
    }
    sendJson(res, 200, { login: 'runner-operator', scopes: pat?.scopes ?? ['session'] })
    return
  }

  if (method === 'POST' && match(url, method, '/oauth/token')) {
    await readBody(req)
    if (!authenticate(state, req)) {
      sendJson(res, 401, { error: 'invalid_client' })
      return
    }
    sendJson(res, 200, {
      access_token: mint('mh_fake_oauth_'), token_type: 'Bearer', expires_in: 3600, scope: 'repo read:user',
    })
    return
  }
  if (match(url, method, '/oauth/authorize')) {
    if (!authenticate(state, req)) {
      sendJson(res, 401, { error: 'login_required' })
      return
    }
    sendJson(res, 200, { code: mint('mh_fake_code_'), state: url.search.get('state') ?? '' })
    return
  }
  if (match(url, method, '/.well-known/oauth-authorization-server')) {
    sendJson(res, 200, {
      issuer: 'http://scm.invalid', authorization_endpoint: '/oauth/authorize',
      token_endpoint: '/oauth/token', scopes_supported: ['repo', 'read:user', 'runner:stream'],
    })
    return
  }

  if (match(url, method, '/scopes')) {
    sendJson(res, 200, { scopes: ['repo', 'repo:read', 'repo:write', 'org:admin', 'team:manage', 'runner:stream'] })
    return
  }
  if (match(url, method, '/tenants')) {
    sendJson(res, 200, {
      tenants: state.distro.map((tenant) => ({ id: tenant.id, slug: tenant.slug, name: tenant.name })),
    })
    return
  }
  if (match(url, method, '/audit')) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    sendJson(res, 200, {
      events: state.audit
        .filter((event) => event.detail.tenantId === session.tenantId)
        .slice(-50)
        .map((event) => ({ kind: event.kind, ts: event.ts })),
    })
    return
  }
  if (match(url, method, '/health/history')) {
    sendJson(res, 200, { history: [] })
    return
  }
  if (match(url, method, '/rate-limit')) {
    sendJson(res, 200, { limit: 5000, remaining: 4999, reset: 60 })
    return
  }
  if (match(url, method, '/keys')) {
    sendJson(res, 200, { keys: [{ kid: 'mh_fake_key_1', algorithm: 'RS256', rotatedAt: 0 }] })
    return
  }

  sendJson(res, 404, { error: 'not found', service: 'scm' })
}
