// Tenant control plane: REST + GraphQL projects, deployments, automations, secrets and searches.
import { randomBytes } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Egress } from '../../../lib/egress.ts'
import {
  readBody, parseJson, sendJson, sendText, bearer, header, runIdOf, match, parseUrl,
} from './http.ts'
import type { LabState, TenantKey } from './shared.ts'
import {
  authenticate, authorizeHeader, canContribute, canManage, digest, hasTenantMembership, hmacHex, patByToken,
  resolveCaller, roleOf, safeEqualHex, sessionTenantOk,
} from './policy.ts'
import {
  buildById, convergeBuild, deploymentById, projectById, tenantById, tenantBySlug,
} from './state.ts'

export interface ApiDeps {
  egress: Egress
}

function sessionAuth(state: LabState, req: IncomingMessage, res: ServerResponse) {
  const session = authenticate(state, req)
  if (!session) {
    sendJson(res, 401, { error: 'session required' })
    return null
  }
  if (!sessionTenantOk(state.profile, session)) {
    sendJson(res, 403, { error: 'session not valid for this tenant' })
    return null
  }
  return session
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
      projects: state.projects.length, builds: state.builds.length,
      deployments: state.deployments.length, automations: state.automations.length,
    })
    return
  }

  if (method === 'POST' && match(url, method, at('/auth/login'))) {
    const raw = await readBody(req)
    const response = await deps.egress.fetch('scm', '/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-guardian-run-id': runId },
      body: raw,
    })
    await proxy(res, response)
    return
  }

  if (match(url, method, at('/me'))) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    sendJson(res, 200, {
      userId: session.userId, tenant: session.tenantId, role: session.role,
      origin: session.originPersona,
      permissions: {
        org: session.role === 'owner' || session.role === 'admin' ? 'admin' : session.role,
        team: session.role !== 'viewer' ? 'manage' : 'read',
      },
    })
    return
  }

  if (match(url, method, at('/orgs'))) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    sendJson(res, 200, {
      orgs: state.distro
        .filter((tenant) => hasTenantMembership(state, session, tenant.id))
        .map((tenant) => ({
          id: tenant.id, slug: tenant.slug, name: tenant.name, role: roleOf(state, session, tenant.id),
        })),
    })
    return
  }

  const org = match(url, method, at('/orgs/:org'))
  if (org) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    const tenantId = tenantById(state, org[0]!)
    if (!tenantId || !hasTenantMembership(state, session, tenantId)) {
      sendJson(res, 404, { error: 'unknown org' })
      return
    }
    sendJson(res, 200, { org: state.orgs[tenantId], role: roleOf(state, session, tenantId) })
    return
  }

  if (match(url, method, at('/projects'))) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    sendJson(res, 200, {
      projects: state.projects
        .filter((project) => hasTenantMembership(state, session, project.tenantId))
        .map((project) => ({
          id: project.id, slug: project.slug, name: project.name,
          tenant: project.tenantId, visibility: project.visibility, state: project.state,
        })),
    })
    return
  }

  const projectGet = match(url, method, at('/projects/:id'))
  if (projectGet) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    const project = projectById(state, projectGet[0]!)
    if (!project || !hasTenantMembership(state, session, project.tenantId)) {
      sendJson(res, 404, { error: 'unknown project' })
      return
    }
    sendJson(res, 200, { project })
    return
  }

  const transfer = match(url, method, at('/projects/:id/transfer'))
  if (transfer) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    const project = projectById(state, transfer[0]!)
    if (!project) {
      sendJson(res, 404, { error: 'unknown project' })
      return
    }
    const body = parseJson<{
      destinationTenant?: string; artifactHandle?: string; originCredential?: string
    }>(await readBody(req))
    const destination = (body?.destinationTenant ? tenantBySlug(state, body.destinationTenant) : null) ??
      session.tenantId
    const sourceRole = roleOf(state, session, project.tenantId)
    const destRole = roleOf(state, session, destination)
    // Transfers always need some standing in both tenants; the policy below decides how much.
    if (!sourceRole || !destRole) {
      sendJson(res, 404, { error: 'unknown project' })
      return
    }
    if (state.profile.transferDualAdmin && (
      (sourceRole !== 'admin' && sourceRole !== 'owner') || (destRole !== 'admin' && destRole !== 'owner')
    )) {
      state.emit('project.transfer_denied', {
        projectId: project.id, tenantId: project.tenantId, destination,
        reason: 'dual_admin_required', runId,
      }, session.originPersona)
      sendJson(res, 403, { error: 'transfer requires admin on both tenants' })
      return
    }
    if (state.profile.transferRequiresLivePat) {
      const originToken = body?.originCredential ?? ''
      const originPat = originToken ? patByToken(state, originToken) : null
      const live = originPat ? !originPat.revoked : Boolean(authenticate(state, req))
      if (!live) {
        state.emit('project.transfer_denied', {
          projectId: project.id, tenantId: project.tenantId, destination,
          reason: 'credential_revoked', runId,
        }, session.originPersona)
        sendJson(res, 403, { error: 'source credential is no longer live' })
        return
      }
    }
    // Without owner/admin standing in the source tenant, the caller must cite the project's current
    // build artifact as proof of build custody.
    if (sourceRole !== 'admin' && sourceRole !== 'owner') {
      const handle = body?.artifactHandle ?? ''
      const custody = handle
        ? state.builds.find((build) => build.projectId === project.id && build.artifactHandle === handle) ?? null
        : null
      if (custody) convergeBuild(state, custody.id)
      if (!custody || custody.status !== 'ready') {
        state.emit('project.transfer_denied', {
          projectId: project.id, tenantId: project.tenantId, destination,
          reason: 'artifact_required', runId,
        }, session.originPersona)
        sendJson(res, 403, { error: 'transfer requires the current build artifact' })
        return
      }
    }
    project.transferredToTenant = destination
    const transferId = `mh_xfer_${digest(`${project.id}:${destination}:${runId}`).slice(0, 10)}`
    state.emit('project.transferred', {
      projectId: project.id,
      fromTenant: project.tenantId,
      toTenant: destination,
      transferId,
      artifactDigest: body?.artifactHandle ? digest(body.artifactHandle) : '',
      runId,
    }, session.originPersona)
    sendJson(res, 200, { project, transferId, destination })
    return
  }

  const projectWebhooks = match(url, method, at('/projects/:id/webhooks'))
  if (projectWebhooks) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    const raw = await readBody(req)
    const response = await deps.egress.fetch('scm', `/repos/${encodeURIComponent(projectWebhooks[0]!)}/webhooks`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-guardian-run-id': runId,
        authorization: `Bearer ${session.token}`,
      },
      body: raw,
    })
    await proxy(res, response)
    return
  }

  const projectDeliveries = match(url, method, at('/projects/:id/webhooks/:wid/deliveries'))
  if (projectDeliveries) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    const path = `/repos/${encodeURIComponent(projectDeliveries[0]!)}` +
      `/webhooks/${encodeURIComponent(projectDeliveries[1]!)}/deliveries`
    const response = await deps.egress.fetch('scm', path, {
      headers: { 'x-guardian-run-id': runId, authorization: `Bearer ${session.token}` },
    })
    await proxy(res, response)
    return
  }

  // Pool event feed relayed from the build runner. The runner applies its own credential policy;
  // this route only forwards the caller's credential.
  if (match(url, method, at('/runners/shared/events'))) {
    const credential = authorizeHeader(req)
    if (!credential) {
      sendJson(res, 401, { error: 'credential required' })
      return
    }
    const response = await deps.egress.fetch('runner', '/streams/shared', {
      headers: { 'x-guardian-run-id': runId, authorization: `Bearer ${credential}` },
    })
    await proxy(res, response)
    return
  }

  // Registry integration check: relays a tenant sync to the package registry with the registry
  // credential the caller supplies. The registry applies its own credential and scope policy.
  if (method === 'POST' && match(url, method, at('/integrations/registry/sync'))) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    const raw = await readBody(req)
    const body = parseJson<{ tenant?: string; projectId?: string; registryToken?: string }>(raw)
    const registryToken = header(req, 'x-registry-token') || (typeof body?.registryToken === 'string' ? body.registryToken : '')
    const response = await deps.egress.fetch('registry.internal', '/sync', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-guardian-run-id': runId,
        ...(registryToken ? { 'x-registry-token': registryToken } : {}),
      },
      body: JSON.stringify({ tenant: body?.tenant, projectId: body?.projectId }),
    })
    await proxy(res, response)
    return
  }

  if (match(url, method, at('/search/projects'))) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    const wantedState = (url.search.get('state') ?? 'active') as 'active' | 'archived'
    const wantedVisibility = (url.search.get('visibility') ?? 'private') as 'private' | 'shared'
    const scoped = state.profile.searchFilterParenthesized
    const projects = state.projects.filter((project) => scoped
      ? project.tenantId === session.tenantId && project.state === wantedState &&
        project.visibility === wantedVisibility
      : project.tenantId === session.tenantId || project.state === wantedState ||
        project.visibility === wantedVisibility)
    const leakedTemplate = scoped
      ? null
      : state.webhookTemplates.find((template) =>
        template.tenantId !== session.tenantId && template.state === wantedState &&
        template.visibility === wantedVisibility) ?? null
    state.emit('project.search', {
      query: `state=${wantedState}&visibility=${wantedVisibility}`,
      tenantId: session.tenantId,
      unparenthesized: !scoped,
      resultCount: projects.length,
      leakedTemplateId: leakedTemplate?.id ?? '',
      leakedTenant: leakedTemplate?.tenantId ?? '',
      templateDigest: leakedTemplate ? digest(leakedTemplate.id) : '',
      runId,
    }, session.originPersona)
    sendJson(res, 200, {
      projects: projects.map((project) => ({
        id: project.id, name: project.name, tenant: project.tenantId, state: project.state,
      })),
      webhookTemplates: leakedTemplate ? [{
        id: leakedTemplate.id, name: leakedTemplate.name, tenant: leakedTemplate.tenantId,
        targetHost: leakedTemplate.targetHost, targetPath: leakedTemplate.targetPath,
      }] : [],
    })
    return
  }

  if (method === 'POST' && match(url, method, at('/graphql'))) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    const body = parseJson<{ query?: string; variables?: { id?: string } }>(await readBody(req))
    const query = body?.query ?? ''
    if (!query.includes('ciRun')) {
      sendJson(res, 200, {
        data: {
          viewer: { id: session.userId, tenant: session.tenantId, role: session.role },
          projects: state.projects.filter((project) => project.tenantId === session.tenantId),
        },
      })
      return
    }
    const buildId = body?.variables?.id ?? ''
    const build = buildId ? buildById(state, buildId) : null
    if (!build) {
      sendJson(res, 200, { data: { ciRun: null }, errors: [{ message: 'ciRun not found' }] })
      return
    }
    const project = projectById(state, build.projectId)
    if (!project || project.tenantId !== session.tenantId) {
      sendJson(res, 200, { data: { ciRun: null }, errors: [{ message: 'ciRun not found' }] })
      return
    }
    convergeBuild(state, build.id)
    // Only a build's own preview credential can be projected; most builds carry none.
    const exposed = state.profile.previewEnvLeak && build.status === 'ready' && build.envPreview.runnerToken.length > 0
    const token = exposed ? build.envPreview.runnerToken : ''
    state.emit('ci.env_preview', {
      buildId: build.id,
      projectId: build.projectId,
      tenantId: session.tenantId,
      status: build.status,
      env: build.envPreview.env,
      exposed,
      runnerTokenDigest: token ? digest(token) : '',
      runId: build.runId,
    }, session.originPersona)
    sendJson(res, 200, {
      data: {
        ciRun: {
          id: build.id,
          status: build.status,
          envPreview: token
            ? { env: build.envPreview.env, runnerToken: token, note: build.envPreview.note, expiresIn: 900 }
            : { env: build.envPreview.env, note: 'preview credentials are not exposed through this surface' },
        },
      },
    })
    return
  }

  const deploymentGet = match(url, method, at('/deployments/:id'))
  if (deploymentGet) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    const deployment = deploymentById(state, deploymentGet[0]!)
    if (!deployment || deployment.tenantId !== session.tenantId) {
      sendJson(res, 404, { error: 'unknown deployment' })
      return
    }
    sendJson(res, 200, { deployment })
    return
  }

  const promote = match(url, method, at('/deployments/:id/promote'))
  if (promote) {
    const caller = resolveCaller(state, req)
    if (!caller) {
      sendJson(res, 401, { error: 'credential required' })
      return
    }
    const deployment = deploymentById(state, promote[0]!)
    if (!deployment) {
      sendJson(res, 404, { error: 'unknown deployment' })
      return
    }
    // Promotion is a runner-to-control-plane call; user sessions and tokens cannot promote.
    if (caller.kind !== 'runner' || caller.tenantId !== deployment.tenantId) {
      state.emit('deployment.promote_denied', {
        deploymentId: deployment.id,
        reason: 'credential_kind',
        credentialEnv: caller.env ?? caller.kind,
        runId,
      })
      sendJson(res, 403, { error: 'promotion requires a runner credential' })
      return
    }
    if (state.profile.promoteEnvScope) {
      const envOk = caller.kind === 'runner' && caller.env === 'prod'
      if (!envOk) {
        state.emit('deployment.promote_denied', {
          deploymentId: deployment.id,
          reason: 'environment_scope',
          credentialEnv: caller.env ?? caller.kind,
          runId,
        })
        sendJson(res, 403, { error: 'credential is not scoped for production' })
        return
      }
    }
    const saToken = `mh_fake_sa_${randomBytes(9).toString('hex')}`
    state.serviceAccounts.push({ token: saToken, tenantId: deployment.tenantId, scope: 'prod', runId })
    deployment.approved = true
    deployment.status = 'approved'
    state.emit('deployment.promoted', {
      deploymentId: deployment.id,
      projectId: deployment.projectId,
      tenantId: deployment.tenantId,
      env: deployment.env,
      envScopeChecked: state.profile.promoteEnvScope,
      credentialKind: caller.kind,
      credentialEnv: caller.env ?? '',
      tokenDigest: caller.kind === 'runner' ? digest(caller.env === 'dev'
        ? state.plan.secrets.devRunnerToken
        : state.plan.secrets.prodRunnerToken) : '',
      saTokenDigest: digest(saToken),
      saScope: 'prod',
      runId,
    })
    sendJson(res, 200, { deployment, serviceAccountToken: saToken, scope: 'prod' })
    return
  }

  if (match(url, method, at('/secrets'))) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    sendJson(res, 200, {
      secrets: state.secrets
        .filter((secret) => secret.tenantId === session.tenantId)
        .map((secret) => ({
          id: secret.id, name: secret.name, scope: secret.scope,
          masked: true, value: 'mh_fake_masked',
        })),
    })
    return
  }

  if (method === 'POST' && match(url, method, at('/secrets/batch'))) {
    const caller = resolveCaller(state, req)
    if (!caller) {
      sendJson(res, 401, { error: 'credential required' })
      return
    }
    // Unmasked batch reads are reserved for deployment service accounts.
    if (caller.kind !== 'service-account') {
      sendJson(res, 403, { error: 'service account credential required' })
      return
    }
    const body = parseJson<{ ids?: string[]; mutate?: boolean }>(await readBody(req))
    const ids = body?.ids ?? []
    if (ids.length === 0) {
      sendJson(res, 400, { error: 'ids required' })
      return
    }
    const callerTenant = caller.tenantId ?? 'org_a'
    const allScoped = state.profile.secretsBatchAllIds
    const checked = allScoped ? ids : ids.slice(0, 1)
    for (const id of checked) {
      const secret = state.secrets.find((item) => item.id === id)
      if (!secret || secret.tenantId !== callerTenant) {
        state.emit('secrets.batch_denied', { secretId: id, tenantId: callerTenant, runId })
        sendJson(res, 403, { error: 'secret is outside the caller tenant' })
        return
      }
    }
    const processed = ids
      .map((id) => state.secrets.find((item) => item.id === id))
      .filter((secret): secret is NonNullable<typeof secret> => Boolean(secret))
    const victim = processed.find((secret) => secret.tenantId !== callerTenant) ?? null
    const own = processed.find((secret) => secret.tenantId === callerTenant) ?? null
    state.emit('secrets.batch_processed', {
      ownId: own?.id ?? '',
      victimId: victim?.id ?? '',
      victimTenant: victim?.tenantId ?? '',
      victimKeyDigest: victim ? digest(victim.value) : '',
      byTenant: callerTenant,
      credentialDigest: digest(authorizeHeader(req)),
      partialAuthz: !allScoped && Boolean(victim),
      processedCount: processed.length,
      runId,
    })
    const response = processed.map((secret) => ({
      id: secret.id, name: secret.name, tenant: secret.tenantId,
      scope: secret.scope, value: secret.value,
    }))
    if (body?.mutate && victim && !allScoped) {
      victim.value = `mh_fake_signing_rotated_${digest(`${victim.id}:${runId}`).slice(0, 16)}`
    }
    sendJson(res, 200, { processed: response, partialAuthz: !allScoped && Boolean(victim) })
    return
  }

  if (match(url, method, at('/automations'))) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    if (method === 'GET') {
      sendJson(res, 200, {
        automations: state.automations.filter((item) => item.tenantId === session.tenantId),
      })
      return
    }
    const body = parseJson<{ projectId?: string; name?: string; schedule?: string }>(await readBody(req))
    if (!body?.projectId) {
      sendJson(res, 400, { error: 'projectId required' })
      return
    }
    const target = projectById(state, body.projectId)
    if (!target || target.tenantId !== session.tenantId) {
      sendJson(res, 404, { error: 'unknown project' })
      return
    }
    if (!canContribute(roleOf(state, session, session.tenantId))) {
      sendJson(res, 403, { error: 'automations require contributor access' })
      return
    }
    const inherited = state.profile.automationInheritAdmin
    const automation = {
      id: `mh_auto_${state.automations.length + 1}_${digest(`${runId}:${body.projectId}`).slice(0, 8)}`,
      projectId: body.projectId,
      tenantId: session.tenantId,
      roleTemplate: inherited ? 'org:admin' : 'project:member',
      autoRelease: inherited,
      runId,
    }
    state.automations.push(automation)
    state.emit('automation.created', {
      automationId: automation.id,
      projectId: automation.projectId,
      tenantId: automation.tenantId,
      inheritedRole: automation.roleTemplate,
      autoRelease: automation.autoRelease,
      schedule: body.schedule ?? 'on-dispute',
      runId,
    }, session.originPersona)
    sendJson(res, 201, { automation })
    return
  }

  const dispute = match(url, method, at('/deployments/:id/dispute'))
  if (dispute) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    const deployment = deploymentById(state, dispute[0]!)
    if (!deployment || deployment.tenantId !== session.tenantId) {
      sendJson(res, 404, { error: 'unknown deployment' })
      return
    }
    if (!canContribute(roleOf(state, session, deployment.tenantId))) {
      sendJson(res, 403, { error: 'disputes require contributor access' })
      return
    }
    const body = parseJson<{ automationId?: string }>(await readBody(req))
    const automationId = body?.automationId ?? ''
    // Only an auto-releasing automation registered for this deployment's project keeps a schedule.
    const automation = state.automations.find((item) =>
      item.id === automationId && item.tenantId === deployment.tenantId &&
      item.projectId === deployment.projectId) ?? null
    deployment.disputed = true
    deployment.status = 'disputed'
    if (state.profile.disputeKeepsSchedule && automation?.autoRelease) deployment.autoReleaseScheduled = true
    state.emit('deployment.disputed', {
      deploymentId: deployment.id,
      projectId: deployment.projectId,
      tenantId: deployment.tenantId,
      automationId,
      automationDigest: automationId ? digest(automationId) : '',
      autoReleaseScheduled: deployment.autoReleaseScheduled,
      runId,
    }, session.originPersona)
    sendJson(res, 200, { deployment })
    return
  }

  const release = match(url, method, at('/deployments/:id/release'))
  if (release) {
    const caller = resolveCaller(state, req)
    if (!caller) {
      sendJson(res, 401, { error: 'credential required' })
      return
    }
    const deployment = deploymentById(state, release[0]!)
    if (!deployment || caller.tenantId !== deployment.tenantId) {
      sendJson(res, 404, { error: 'unknown deployment' })
      return
    }
    if ((caller.kind === 'session' || caller.kind === 'pat') && !canContribute(caller.role)) {
      sendJson(res, 403, { error: 'releases require contributor access' })
      return
    }
    const body = parseJson<{ manifest?: string; signature?: string; version?: string }>(await readBody(req))
    const releaseId = `mh_rel_${randomBytes(6).toString('hex')}`
    const denied = (): void => {
      state.emit('release.denied', {
        deploymentId: deployment.id,
        tenantId: deployment.tenantId,
        reason: 'approval_required',
        autoReleaseScheduled: deployment.autoReleaseScheduled,
        runId,
      }, caller.persona)
      sendJson(res, 409, { error: 'deployment is not approved for release' })
    }
    if (deployment.id === state.plan.ids.deploymentProdId) {
      if (!deployment.approved || state.profile.promoteEnvScope) {
        denied()
        return
      }
      const manifest = body?.manifest ?? ''
      const signature = body?.signature ?? ''
      if (!manifest || !safeEqualHex(signature, hmacHex(state.plan.secrets.prodSigningKey, manifest))) {
        state.emit('release.signature_denied', { deploymentId: deployment.id, runId })
        sendJson(res, 403, { error: 'release manifest signature is not valid' })
        return
      }
      deployment.status = 'released'
      deployment.releaseId = releaseId
      state.emit('deployment.released', {
        deploymentId: deployment.id,
        projectId: deployment.projectId,
        tenantId: deployment.tenantId,
        env: deployment.env,
        releaseId,
        releaseDigest: digest(`${releaseId}:${manifest}`),
        signedWith: 'prod-signing-key',
        keyDigest: digest(state.plan.secrets.prodSigningKey),
        approval: 'automation',
        version: body?.version ?? '2026.11.0',
        runId,
      })
      sendJson(res, 200, { deployment, releaseId, env: deployment.env })
      return
    }
    if (!deployment.approved && !deployment.autoReleaseScheduled) {
      denied()
      return
    }
    if (state.profile.autoReleaseRequiresApproval && !deployment.approved) {
      denied()
      return
    }
    deployment.status = 'released'
    deployment.releaseId = releaseId
    state.emit('deployment.released', {
      deploymentId: deployment.id,
      projectId: deployment.projectId,
      tenantId: deployment.tenantId,
      env: deployment.env,
      releaseId,
      releaseDigest: digest(`${releaseId}:${deployment.id}`),
      signedWith: 'automation-schedule',
      keyDigest: '',
      approval: 'automation',
      version: body?.version ?? '2026.11.1',
      runId,
    })
    sendJson(res, 200, { deployment, releaseId, env: deployment.env })
    return
  }

  if (method === 'POST' && match(url, method, at('/keys/rotate'))) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    if (!canManage(roleOf(state, session, session.tenantId))) {
      sendJson(res, 403, { error: 'key rotation requires owner or admin' })
      return
    }
    state.emit('keys.rotated', { tenantId: session.tenantId, keyId: 'mh_fake_signing_1', runId }, session.originPersona)
    sendJson(res, 200, { ok: true, keyId: 'mh_fake_signing_1' })
    return
  }

  const benign: Record<string, unknown> = {
    '/runners': { runners: [{ id: 'shared-1', pool: 'shared' }, { id: 'hosted-2', pool: 'hosted' }] },
    '/pipelines': { pipelines: [{ id: 'mh_pipe_1', stages: ['build', 'test', 'deploy'] }] },
    '/environments': { environments: ['preview', 'staging', 'prod'] },
    '/artifacts': { artifacts: [{ id: 'mh_art_1', retentionDays: 30 }] },
    '/settings': { settings: { region: 'us-east-1', sso: 'optional', retentionDays: 30 } },
    '/usage': { minutes: 1280, storageGb: 12, runners: 3 },
    '/billing': { plan: 'scale', seats: 25, renewal: '2027-01-01' },
    '/members': { members: state.users.filter((user) => !user.bot).length },
    '/notifications': { notifications: [{ id: 'mh_note_1', kind: 'build.succeeded' }] },
    '/integrations': { integrations: [{ id: 'mh_int_1', kind: 'chat' }, { id: 'mh_int_2', kind: 'registry' }] },
    '/teams': { teams: [{ id: 'mh_team_1', role: 'developers' }, { id: 'mh_team_2', role: 'release' }] },
  }
  for (const [path, payload] of Object.entries(benign)) {
    if (match(url, method, at(path))) {
      const session = sessionAuth(state, req, res)
      if (!session) return
      if (path === '/members') {
        sendJson(res, 200, {
          members: state.users.filter((user) => !user.bot && user.rolesByTenant[session.tenantId]).length,
        })
        return
      }
      sendJson(res, 200, payload)
      return
    }
  }

  if (match(url, method, at('/audit'))) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    sendJson(res, 200, {
      events: state.audit
        .filter((event) => event.detail.tenantId === session.tenantId)
        .slice(-100)
        .map((event) => ({
          kind: event.kind, ts: event.ts, actor: event.actorPersona,
        })),
    })
    return
  }

  if (match(url, method, at('/tokens'))) {
    const session = sessionAuth(state, req, res)
    if (!session) return
    sendJson(res, 200, {
      tokens: state.pats
        .filter((pat) => pat.userId === session.userId && pat.tenantId === session.tenantId)
        .map((pat) => ({ id: pat.id, scopes: pat.scopes, revoked: pat.revoked })),
    })
    return
  }

  if (match(url, method, at('/ping'))) {
    sendText(res, 200, 'pong')
    return
  }
  if (bearer(req).startsWith('mh_fake_sa_') && !url.pathname.startsWith(p)) {
    sendJson(res, 400, { error: 'service credentials are scoped to deployment routes' })
    return
  }

  sendJson(res, 404, { error: 'not found', service: 'api' })
}
