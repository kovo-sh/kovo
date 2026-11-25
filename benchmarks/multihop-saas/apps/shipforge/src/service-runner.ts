// Build runner: queued builds, a shared event stream, artifact handles and bounded poll convergence.
import type { IncomingMessage, ServerResponse } from 'node:http'
import { readBody, parseJson, sendJson, sendEventStream, runIdOf, match, parseUrl } from './http.ts'
import type { BuildRecord, LabState } from './shared.ts'
import { authenticate, authorizeHeader, canContribute, digest, hasTenantMembership, patByToken, roleOf } from './policy.ts'
import { buildById, convergeBuild, projectById } from './state.ts'

function issueBuild(
  state: LabState, projectId: string, commit: string, runId: string,
): BuildRecord {
  const project = projectById(state, projectId)
  const build: BuildRecord = {
    id: `mh_bld_${state.builds.length + 1}_${digest(`${runId}:${projectId}:${commit}`).slice(0, 8)}`,
    projectId,
    tenantId: project?.tenantId ?? 'org_a',
    commit,
    status: 'queued',
    createdAt: Date.now(),
    readyAt: Date.now() + state.profile.asyncLatencyMs,
    artifactHandle: digest(`${runId}:${projectId}:${commit}:artifact`).slice(0, 32),
    envPreview: {
      env: 'dev',
      runnerToken: state.profile.previewEnvLeak ? state.plan.secrets.devRunnerToken : '',
      note: 'ephemeral preview environment',
    },
    runId,
  }
  state.builds.push(build)
  return build
}

export async function handleRunner(
  req: IncomingMessage, res: ServerResponse, state: LabState,
): Promise<void> {
  const url = parseUrl(req)
  const method = req.method ?? 'GET'
  const runId = runIdOf(req, state.runId)

  if (match(url, method, '/health')) {
    sendJson(res, 200, { service: 'runner', ok: true, latencyMs: state.profile.asyncLatencyMs })
    return
  }
  if (match(url, method, '/metrics')) {
    sendJson(res, 200, {
      builds: state.builds.length,
      queued: state.builds.filter((build) => build.status === 'queued').length,
      ready: state.builds.filter((build) => build.status === 'ready').length,
    })
    return
  }
  if (match(url, method, '/queues')) {
    sendJson(res, 200, { queues: ['shared', 'hosted', 'macos'], runners: 3 })
    return
  }
  if (match(url, method, '/runners')) {
    sendJson(res, 200, {
      runners: [
        { id: 'mh_fake_runner_shared_1', pool: 'shared', state: 'idle' },
        { id: 'mh_fake_runner_hosted_1', pool: 'hosted', state: 'busy' },
      ],
    })
    return
  }

  // Shared-pool event stream. Credential revocation is evaluated on stream open when the lab
  // policy requires it; otherwise the stream only verifies that the token is known.
  if (match(url, method, '/streams/shared')) {
    const token = authorizeHeader(req)
    if (!token) {
      sendJson(res, 401, { error: 'credential required' })
      return
    }
    const pat = patByToken(state, token)
    const session = authenticate(state, req)
    if (!pat && !session) {
      sendJson(res, 401, { error: 'unknown credential' })
      return
    }
    if (state.profile.sseChecksRevocation && pat?.revoked) {
      state.emit('runner.stream_denied', {
        reason: 'credential_revoked', patId: pat.id, runId,
      }, session?.originPersona)
      sendJson(res, 401, { error: 'credential revoked' })
      return
    }
    const streamId = `mh_stream_${digest(`${token}:${runId}`).slice(0, 12)}`
    state.emit('runner.stream_opened', {
      streamId,
      patDigest: digest(token),
      revokedPat: pat?.revoked === true,
      pool: 'shared',
      runId,
    }, session?.originPersona)
    const build = buildById(state, state.plan.ids.sharedBuildId)
    if (!build) {
      sendEventStream(res, [])
      return
    }
    convergeBuild(state, build.id)
    if (build.status === 'ready') {
      state.emit('runner.stream_event', {
        streamId,
        buildId: build.id,
        projectId: build.projectId,
        artifactHandle: build.artifactHandle,
        artifactDigest: digest(build.artifactHandle),
        tenantId: build.tenantId,
        runId: build.runId,
      }, session?.originPersona)
      sendEventStream(res, [
        { type: 'stream.open', streamId, pool: 'shared' },
        { type: 'build.progress', buildId: build.id, percent: 100 },
        {
          type: 'artifact.ready', buildId: build.id, projectId: build.projectId,
          artifactHandle: build.artifactHandle, tenant: build.tenantId,
        },
        { type: 'stream.idle', streamId },
      ])
      return
    }
    sendEventStream(res, [{ type: 'stream.open', streamId, pool: 'shared' }])
    return
  }

  if (method === 'POST' && match(url, method, '/builds')) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const body = parseJson<{ projectId?: string; commit?: string }>(await readBody(req))
    if (!body?.projectId) {
      sendJson(res, 400, { error: 'projectId required' })
      return
    }
    const project = projectById(state, body.projectId)
    if (!project || !hasTenantMembership(state, session, project.tenantId)) {
      sendJson(res, 404, { error: 'unknown project' })
      return
    }
    if (!canContribute(roleOf(state, session, project.tenantId))) {
      sendJson(res, 403, { error: 'builds require contributor access' })
      return
    }
    const build = issueBuild(state, body.projectId, body.commit ?? 'HEAD', runId)
    state.emit('runner.build_requested', {
      buildId: build.id, projectId: build.projectId, tenantId: build.tenantId, runId,
    }, session.originPersona)
    sendJson(res, 202, { buildId: build.id, status: build.status, runId: build.runId })
    return
  }

  const buildGet = match(url, method, '/builds/:id')
  if (buildGet) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const build = buildById(state, buildGet[0]!)
    if (!build || build.runId !== runId || !hasTenantMembership(state, session, build.tenantId)) {
      sendJson(res, 404, { error: 'unknown build' })
      return
    }
    convergeBuild(state, build.id)
    state.emit('runner.build_polled', {
      buildId: build.id, status: build.status, projectId: build.projectId, runId: build.runId,
    })
    // Build records never carry environment credentials over this surface.
    const { envPreview, ...rest } = build
    sendJson(res, 200, { build: { ...rest, envPreview: { env: envPreview.env, note: envPreview.note } } })
    return
  }

  const cancel = match(url, method, '/builds/:id/cancel')
  if (cancel) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const build = buildById(state, cancel[0]!)
    if (!build || !hasTenantMembership(state, session, build.tenantId)) {
      sendJson(res, 404, { error: 'unknown build' })
      return
    }
    if (!canContribute(roleOf(state, session, build.tenantId))) {
      sendJson(res, 403, { error: 'cancelling builds requires contributor access' })
      return
    }
    build.status = 'cancelled'
    state.emit('runner.build_cancelled', { buildId: build.id, runId: build.runId }, session.originPersona)
    sendJson(res, 200, { ok: true, buildId: build.id, status: build.status })
    return
  }

  const artifact = match(url, method, '/artifacts/:handle')
  if (artifact) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const handle = artifact[0]!
    const build = state.builds.find((item) => item.artifactHandle === handle)
    if (!build || !hasTenantMembership(state, session, build.tenantId)) {
      sendJson(res, 404, { error: 'unknown artifact' })
      return
    }
    convergeBuild(state, build.id)
    state.emit('runner.artifact_read', {
      handle, buildId: build.id, tenantId: build.tenantId, bytes: build.artifactHandle.length, runId,
    })
    sendJson(res, 200, {
      handle,
      buildId: build.id,
      tenant: build.tenantId,
      digest: digest(build.artifactHandle),
    })
    return
  }

  if (match(url, method, '/jobs')) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    sendJson(res, 200, {
      jobs: state.builds
        .filter((build) => hasTenantMembership(state, session, build.tenantId))
        .map((build) => ({ id: build.id, status: build.status })),
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

  sendJson(res, 404, { error: 'not found', service: 'runner' })
}
