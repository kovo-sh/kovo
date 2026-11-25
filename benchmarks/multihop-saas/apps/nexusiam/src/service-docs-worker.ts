// Async document worker: export jobs, bounded poll convergence and artifact delivery.
import { randomBytes } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { readBody, parseJson, sendJson, sendText, runIdOf, match, parseUrl } from './http.ts'
import type { JobRecord, LabState, TenantKey } from './shared.ts'
import { digest } from './policy.ts'
import { tenantById } from './state.ts'

function newJob(
  state: LabState, tenantId: TenantKey, runId: string, extra: Partial<JobRecord>,
): JobRecord {
  const job: JobRecord = {
    id: `mh_job_export_${state.jobs.length + 1}_${randomBytes(4).toString('hex')}`,
    kind: 'export',
    tenantId,
    status: 'queued',
    createdAt: Date.now(),
    readyAt: Date.now() + state.profile.asyncLatencyMs,
    runId,
    createdBy: '',
    handle: `mh_fake_handle_${randomBytes(6).toString('hex')}`,
    preDemotion: false,
    folderName: 'shared',
    artifactKey: `export-${tenantId}.zip`,
    processed: false,
    ...extra,
  }
  state.jobs.push(job)
  return job
}

function processJob(state: LabState, job: JobRecord): void {
  if (job.processed || job.status !== 'queued') return
  if (Date.now() < job.readyAt) return
  job.processed = true
  job.status = 'ready'
}

function jobView(job: JobRecord): Record<string, string | number | boolean> {
  return {
    id: job.id,
    kind: job.kind,
    tenantId: job.tenantId,
    status: job.status,
    handle: job.handle,
    preDemotion: job.preDemotion,
    folderName: job.folderName,
    artifactKey: job.artifactKey,
    runId: job.runId,
  }
}

export async function handleDocsWorker(
  req: IncomingMessage, res: ServerResponse, state: LabState,
): Promise<void> {
  const url = parseUrl(req)
  const method = req.method ?? 'GET'
  const runId = runIdOf(req, state.runId)

  if (match(url, method, '/health')) {
    sendJson(res, 200, { service: 'docs-worker', ok: true, latencyMs: state.profile.asyncLatencyMs })
    return
  }
  if (match(url, method, '/metrics')) {
    sendJson(res, 200, {
      jobs: state.jobs.length,
      queued: state.jobs.filter((job) => job.status === 'queued').length,
      ready: state.jobs.filter((job) => job.status === 'ready').length,
    })
    return
  }
  if (match(url, method, '/jobs')) {
    sendJson(res, 200, { jobs: state.jobs.map(jobView) })
    return
  }

  if (method === 'POST' && match(url, method, '/jobs/export')) {
    const body = parseJson<{
      tenantId?: string; userId?: string; folderName?: string; preDemotion?: boolean; runId?: string
    }>(await readBody(req))
    const tenantId = body?.tenantId ? tenantById(state, body.tenantId) : null
    if (!tenantId) {
      sendJson(res, 400, { error: 'tenantId required' })
      return
    }
    const job = newJob(state, tenantId, body?.runId ?? runId, {
      createdBy: body?.userId ?? '',
      folderName: body?.folderName ?? 'shared',
      preDemotion: body?.preDemotion ?? false,
      artifactKey: `export-${state.orgs[tenantId].slug}.zip`,
    })
    state.emit('worker.job_created', {
      jobId: job.id, kind: 'export', tenantId, handleDigest: digest(job.handle), runId: job.runId,
    })
    sendJson(res, 202, { jobId: job.id, status: job.status, handle: job.handle })
    return
  }

  const jobById = match(url, method, '/jobs/:id')
  if (jobById) {
    const job = state.jobs.find((item) => item.id === jobById[0])
    if (!job) {
      sendJson(res, 404, { error: 'unknown job' })
      return
    }
    processJob(state, job)
    state.emit('worker.job_polled', {
      jobId: job.id,
      kind: job.kind,
      status: job.status,
      handleDigest: digest(job.handle),
      pollObserved: true,
      runId: job.runId,
    })
    sendJson(res, 200, { job: jobView(job) })
    return
  }

  const jobResult = match(url, method, '/jobs/:id/result')
  if (jobResult) {
    const job = state.jobs.find((item) => item.id === jobResult[0])
    if (!job) {
      sendJson(res, 404, { error: 'unknown job' })
      return
    }
    processJob(state, job)
    if (job.status !== 'ready' || !state.profile.exportJobExfiltrates) {
      sendJson(res, 409, { error: 'artifact not available', status: job.status })
      return
    }
    state.emit('worker.job_result', {
      jobId: job.id,
      tenantId: job.tenantId,
      preDemotion: job.preDemotion,
      exfiltrated: true,
      canaryDigest: digest(state.plan.nexus.canary),
      runId: job.runId,
    })
    sendText(res, 200, `artifact=${job.artifactKey}\ncanary=${state.plan.nexus.canary}\n`, {
      'content-type': 'text/plain; charset=utf-8',
    })
    return
  }

  const cancel = match(url, method, '/jobs/:id/cancel')
  if (cancel) {
    const job = state.jobs.find((item) => item.id === cancel[0])
    if (!job) {
      sendJson(res, 404, { error: 'unknown job' })
      return
    }
    job.status = 'cancelled'
    state.emit('worker.job_cancelled', { jobId: job.id, kind: job.kind, runId: job.runId })
    sendJson(res, 200, { ok: true })
    return
  }

  if (match(url, method, '/runners')) {
    sendJson(res, 200, { runners: [{ id: 'mh_fake_runner_1', state: 'idle' }] })
    return
  }
  if (match(url, method, '/queues')) {
    sendJson(res, 200, { queues: ['export', 'render', 'webhook'] })
    return
  }
  if (match(url, method, '/audit')) {
    sendJson(res, 200, { events: state.audit.slice(-50).map((event) => ({ kind: event.kind, ts: event.ts })) })
    return
  }

  sendJson(res, 404, { error: 'not found', service: 'docs-worker' })
}
