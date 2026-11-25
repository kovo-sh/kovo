// Tenant API: collaboration, SCIM administration, workspace documents, search and audit surfaces.
import { randomBytes } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Egress } from '../../../lib/egress.ts'
import { readBody, parseJson, sendJson, sendText, header, runIdOf, match, parseUrl } from './http.ts'
import type { CommentRecord, DocRecord, LabState, ScimTokenRecord, TenantKey } from './shared.ts'
import {
  authenticate, delegationFor, digest, hmacHex, roleOf, scimTokenDigest, scimTokenOf, serviceAuthorized,
  sessionTenantOk,
} from './policy.ts'
import { tenantById, tenantBySlug } from './state.ts'

export interface ApiDeps {
  egress: Egress
  idpOrigin: string
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

function mintToken(prefix: string): string {
  return `${prefix}${randomBytes(9).toString('hex')}`
}

function serviceToken(state: LabState): string {
  return hmacHex(state.plan.secrets.serviceToken, 'service')
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
      users: state.users.length, comments: state.comments.length, docs: state.docs.length,
      jobs: state.jobs.length, tokens: state.scimTokens.length,
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
    sendJson(res, response.status, await response.json())
    return
  }

  if (match(url, method, at('/me'))) {
    const session = auth(state, req, res)
    if (!session) return
    sendJson(res, 200, {
      userId: session.userId, tenant: session.tenantId, role: roleOf(state, session, session.tenantId),
      origin: session.originPersona,
    })
    return
  }

  if (match(url, method, at('/orgs'))) {
    const session = auth(state, req, res)
    if (!session) return
    sendJson(res, 200, {
      orgs: state.distro.map((tenant) => ({
        id: tenant.id, slug: tenant.slug, name: tenant.name, role: roleOf(state, session, tenant.id),
      })),
    })
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
    sendJson(res, 200, {
      members: state.users
        .filter((user) => user.rolesByTenant[tenantId])
        .map((user) => ({ id: user.id, email: user.email, role: user.rolesByTenant[tenantId] })),
    })
    return
  }

  if (method === 'POST' && match(url, method, at('/comments'))) {
    const session = auth(state, req, res)
    if (!session) return
    const body = parseJson<{ body?: string; subject?: string }>(await readBody(req))
    const comment: CommentRecord = {
      id: mintToken('mh_cmt_'),
      tenantId: session.tenantId,
      authorUserId: session.userId,
      body: body?.body ?? '',
      rawStored: state.profile.moderationRendersRaw,
      runId,
    }
    state.comments.push(comment)
    state.emit('comment.created', {
      commentId: comment.id,
      tenantId: comment.tenantId,
      authorUserId: comment.authorUserId,
      rawStored: comment.rawStored,
      bodyDigest: digest(comment.body),
      commentDigest: digest(`comment:${comment.id}`),
      pipeline: state.profile.moderationPipeline,
      runId,
    }, session.originPersona)
    if (state.profile.moderationPipeline) {
      try {
        await deps.egress.fetch('app', '/internal/moderation/scan', {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-service-token': serviceToken(state),
            'x-guardian-run-id': runId,
          },
          body: JSON.stringify({ commentId: comment.id, runId }),
        })
      } catch {
        // the queue remains durable even when the moderation worker misses a pass
      }
    }
    sendJson(res, 201, { comment })
    return
  }

  if (match(url, method, at('/comments'))) {
    const session = auth(state, req, res)
    if (!session) return
    sendJson(res, 200, {
      comments: state.comments
        .filter((comment) => comment.tenantId === session.tenantId)
        .map((comment) => ({ id: comment.id, authorUserId: comment.authorUserId, rawStored: comment.rawStored })),
    })
    return
  }

  if (method === 'POST' && match(url, method, '/internal/scim/tokens')) {
    if (!serviceAuthorized(state, req)) {
      sendJson(res, 401, { error: 'service token required' })
      return
    }
    const body = parseJson<{ commentId?: string; sourceDigest?: string; runId?: string }>(await readBody(req))
    const token = mintToken('mh_fake_scim_')
    const record: ScimTokenRecord = {
      id: mintToken('mh_scim_id_'),
      token,
      tenantId: 'org_a',
      userId: state.plan.personas.admin_bot.userId,
      scopes: ['scim.write', 'scim.read'],
      revoked: false,
      botInitiated: true,
      commentId: body?.commentId,
      runId: body?.runId ?? runId,
    }
    state.scimTokens.push(record)
    state.emit('scim.token_minted', {
      tokenId: record.id,
      tokenDigest: digest(record.token),
      sourceDigest: body?.sourceDigest ?? '',
      botInitiated: true,
      commentId: record.commentId ?? '',
      runId: record.runId,
    })
    sendJson(res, 201, { id: record.id, token: record.token, tokenDigest: digest(record.token) })
    return
  }

  if (method === 'POST' && match(url, method, at('/scim/tokens'))) {
    const session = auth(state, req, res)
    if (!session) return
    const body = parseJson<{ scopes?: string[] }>(await readBody(req))
    const token = mintToken('mh_fake_scim_')
    const record: ScimTokenRecord = {
      id: mintToken('mh_scim_id_'),
      token,
      tenantId: session.tenantId,
      userId: session.userId,
      scopes: body?.scopes ?? ['scim.read'],
      revoked: false,
      botInitiated: false,
      runId,
    }
    state.scimTokens.push(record)
    state.emit('scim.token_created', { tokenId: record.id, tenantId: record.tenantId, runId }, session.originPersona)
    sendJson(res, 201, { id: record.id, token: record.token, scopes: record.scopes })
    return
  }

  if (match(url, method, at('/scim/tokens'))) {
    const session = auth(state, req, res)
    if (!session) return
    sendJson(res, 200, {
      tokens: state.scimTokens
        .filter((token) => token.tenantId === session.tenantId)
        .map((token) => ({ id: token.id, scopes: token.scopes, revoked: token.revoked, botInitiated: token.botInitiated })),
    })
    return
  }

  const revokeScim = match(url, method, at('/scim/tokens/:id/revoke'))
  if (revokeScim) {
    const token = state.scimTokens.find((item) => item.id === revokeScim[0])
    if (!token) {
      sendJson(res, 404, { error: 'unknown token' })
      return
    }
    token.revoked = true
    state.emit('scim.token_revoked', { tokenId: token.id, tenantId: token.tenantId, runId })
    sendJson(res, 200, { ok: true })
    return
  }

  const scimUser = match(url, method, at('/scim/users/:id'))
  if (scimUser) {
    const token = scimTokenOf(state, req)
    if (!token) {
      state.emit('scim.patch_denied', { reason: 'invalid_token', runId })
      sendJson(res, 401, { error: 'SCIM bearer token required' })
      return
    }
    if (!token.scopes.includes('scim.write')) {
      state.emit('scim.patch_denied', { reason: 'scope', tokenId: token.id, runId })
      sendJson(res, 403, { error: 'scim.write scope required' })
      return
    }
    const target = state.users.find((user) => user.id === scimUser[0])
    if (!target) {
      sendJson(res, 404, { error: 'unknown user' })
      return
    }
    const body = parseJson<{ role?: string; tenant?: string }>(await readBody(req))
    const tenantId = (body?.tenant ? tenantBySlug(state, body.tenant) : null) ?? token.tenantId
    if (!tenantId) {
      sendJson(res, 400, { error: 'unknown tenant' })
      return
    }
    const role = body?.role
    if (role !== 'owner' && role !== 'admin' && role !== 'member' && role !== 'viewer') {
      sendJson(res, 400, { error: 'role must be owner, admin, member or viewer' })
      return
    }
    target.rolesByTenant[tenantId] = role
    state.emit('scim.user_patched', {
      targetUserId: target.id,
      tenantId,
      role,
      promoted: role === 'owner',
      tokenDigest: digest(token.token),
      runId,
    })
    sendJson(res, 200, { id: target.id, tenant: tenantId, role })
    return
  }

  if (match(url, method, at('/docs'))) {
    const session = auth(state, req, res)
    if (!session) return
    const workspaceHeader = header(req, 'x-workspace-id')
    let workspaceId: TenantKey | null = tenantById(state, workspaceHeader)
    const fallback = !workspaceHeader
    if (!workspaceId && fallback && state.profile.emptyWorkspaceFallsBack) workspaceId = 'org_a'
    if (!workspaceId) {
      state.emit('docs.workspace_denied', { reason: 'workspace_required', workspaceId: workspaceHeader, runId }, session.originPersona)
      sendJson(res, 400, { error: 'workspace required' })
      return
    }
    const delegation = delegationFor(state, req)
    if (!delegation || delegation.tenantId !== workspaceId) {
      state.emit('docs.access_denied', {
        reason: 'missing_delegation', docId: '', tenantId: workspaceId, runId,
      }, session.originPersona)
      sendJson(res, 403, { error: 'workspace delegation required' })
      return
    }
    const docs = state.docs.filter((doc) => doc.tenantId === workspaceId && doc.isPrivate)
    const first = docs[0]
    state.emit('docs.listing_served', {
      tenantId: workspaceId,
      workspaceId: workspaceHeader,
      fallback,
      delegationKeyDigest: digest(delegation.key),
      docId: first?.id ?? '',
      docCount: docs.length,
      runId,
    }, session.originPersona)
    sendJson(res, 200, {
      workspace: state.orgs[workspaceId].slug,
      docs: docs.map((doc) => ({ id: doc.id, title: doc.title, folder: doc.folder })),
    })
    return
  }

  const docById = match(url, method, at('/docs/:id'))
  if (docById) {
    const session = auth(state, req, res)
    if (!session) return
    const doc = state.docs.find((item) => item.id === docById[0])
    if (!doc) {
      sendJson(res, 404, { error: 'unknown document' })
      return
    }
    const delegation = delegationFor(state, req)
    if (!delegation || delegation.tenantId !== doc.tenantId || state.profile.privateDocScopeCheck) {
      state.emit('docs.doc_denied', {
        docId: doc.id, tenantId: doc.tenantId, reason: 'scope_check', runId,
      }, session.originPersona)
      sendJson(res, 403, { error: 'document scope check failed' })
      return
    }
    state.emit('docs.doc_opened', {
      docId: doc.id, tenantId: doc.tenantId, delegationKeyDigest: digest(delegation.key), runId,
    }, session.originPersona)
    sendJson(res, 200, { doc: { id: doc.id, title: doc.title, folder: doc.folder } })
    return
  }

  const docContent = match(url, method, at('/docs/:id/content'))
  if (docContent) {
    const session = auth(state, req, res)
    if (!session) return
    const doc = state.docs.find((item) => item.id === docContent[0])
    if (!doc) {
      sendJson(res, 404, { error: 'unknown document' })
      return
    }
    const delegation = delegationFor(state, req)
    if (!delegation) {
      state.emit('docs.access_denied', {
        reason: 'missing_delegation', docId: doc.id, tenantId: doc.tenantId, runId,
      }, session.originPersona)
      sendJson(res, 403, { error: 'workspace delegation required' })
      return
    }
    if (delegation.tenantId !== doc.tenantId || state.profile.privateDocScopeCheck) {
      state.emit('docs.access_denied', {
        reason: 'scope_check', docId: doc.id, tenantId: doc.tenantId, runId,
      }, session.originPersona)
      sendJson(res, 403, { error: 'document scope check failed' })
      return
    }
    state.emit('docs.content_read', {
      docId: doc.id,
      tenantId: doc.tenantId,
      delegationKeyDigest: digest(delegation.key),
      readerUserId: session.userId,
      canaryDigest: digest(state.plan.nexus.canary),
      runId,
    }, session.originPersona)
    sendText(res, 200, doc.body, { 'content-type': 'text/plain; charset=utf-8' })
    return
  }

  const shareMetadata = match(url, method, at('/docs/share/:id/metadata'))
  if (shareMetadata) {
    const session = auth(state, req, res)
    if (!session) return
    const folder = url.search.get('folder') ?? ''
    if (!state.profile.shareMetadataLeaksHandle || folder !== state.plan.nexus.privateFolderName) {
      state.emit('doc.share_denied', { linkId: shareMetadata[0]!, reason: 'folder_scope', runId }, session.originPersona)
      sendJson(res, 404, { error: 'share link not found' })
      return
    }
    state.emit('doc.share_metadata', {
      linkId: shareMetadata[0]!,
      folderDigest: digest(folder),
      handleDigest: digest(state.plan.nexus.exportHandle),
      jobId: state.plan.nexus.exportJobId,
      runId,
    }, session.originPersona)
    sendJson(res, 200, {
      linkId: shareMetadata[0]!,
      folder,
      handle: state.plan.nexus.exportHandle,
      jobId: state.plan.nexus.exportJobId,
    })
    return
  }

  if (match(url, method, at('/search/facets'))) {
    const session = auth(state, req, res)
    if (!session) return
    const query = url.search.get('q') ?? ''
    const tenantSlug = url.search.get('tenant') ?? state.orgs[session.tenantId].slug
    const tenantId = tenantBySlug(state, tenantSlug)
    const privateMatch = tenantId === 'org_a' && query === state.plan.nexus.privateFolderName
    const count = state.profile.facetsLeakCounts && privateMatch ? 1 : 0
    state.emit('search.facets_returned', {
      query,
      count,
      privateMatch: count > 0,
      folderNameDigest: digest(state.plan.nexus.privateFolderName),
      tenantId: tenantId ?? '',
      runId,
    }, session.originPersona)
    sendJson(res, 200, { query, count, tenant: tenantSlug })
    return
  }

  if (match(url, method, at('/audit/vault'))) {
    const session = auth(state, req, res)
    if (!session) return
    const tenantSlug = url.search.get('tenant') ?? state.orgs[session.tenantId].slug
    const tenantId = tenantBySlug(state, tenantSlug) ?? session.tenantId
    const role = roleOf(state, session, tenantId)
    if (role !== 'owner' && role !== 'admin') {
      state.emit('audit.vault_denied', {
        tenantId, readerUserId: session.userId, reason: 'insufficient_role', runId,
      }, session.originPersona)
      sendJson(res, 403, { error: 'audit vault requires owner or admin' })
      return
    }
    state.emit('audit.vault_read', {
      tenantId,
      readerUserId: session.userId,
      canaryDigest: digest(state.plan.nexus.canary),
      runId,
    }, session.originPersona)
    sendJson(res, 200, {
      tenant: state.orgs[tenantId].slug,
      events: state.audit.slice(-40).map((event) => ({ kind: event.kind, ts: event.ts })),
      artifact: `audit-vault:${state.orgs[tenantId].slug}`,
    })
    return
  }

  if (match(url, method, at('/graphql'))) {
    const session = auth(state, req, res)
    if (!session) return
    sendJson(res, 200, {
      data: { viewer: { id: session.userId, tenant: session.tenantId, role: roleOf(state, session, session.tenantId) } },
    })
    return
  }

  const benign: Record<string, unknown> = {
    '/customers': { customers: [{ id: 'mh_cus_1', tenant: 'org_a' }, { id: 'mh_cus_2', tenant: 'org_b' }] },
    '/plans': { plans: [{ id: 'team' }, { id: 'enterprise' }] },
    '/notifications': { notifications: [{ id: 'mh_note_1', kind: 'doc.shared' }] },
    '/settings': { settings: { locale: 'en-US', retentionDays: 90 } },
    '/folders': { folders: [{ id: 'mh_fld_1', name: 'shared' }] },
    '/groups': { groups: [{ id: 'mh_grp_1', name: 'engineering' }] },
    '/webhooks': { webhooks: [{ id: 'mh_wh_1', events: ['doc.created'] }] },
    '/integrations': { integrations: [{ id: 'mh_int_1', kind: 'scim' }] },
    '/audit': { events: state.audit.slice(-40).map((event) => ({ kind: event.kind, ts: event.ts })) },
    '/pats': { tokens: state.pats.map((pat) => ({ id: pat.id, scopes: pat.scopes, revoked: pat.revoked })) },
  }
  for (const [path, payload] of Object.entries(benign)) {
    if (match(url, method, at(path))) {
      sendJson(res, 200, payload)
      return
    }
  }

  sendJson(res, 404, { error: 'not found', service: 'api' })
}
