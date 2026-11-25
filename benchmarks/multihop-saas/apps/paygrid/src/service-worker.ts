// Async worker: PDF rendering jobs, export jobs and bounded poll convergence.
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Egress } from '../../../lib/egress.ts'
import { readBody, parseJson, sendJson, runIdOf, match, parseUrl } from './http.ts'
import type { JobRecord, LabState, TenantKey } from './shared.ts'

const SALT_PATTERN = /mh_fake_salt_[a-z0-9]+/
const rawFooterJobs = new WeakSet<JobRecord>()

function newJob(
  state: LabState, kind: JobRecord['kind'], tenantId: TenantKey, runId: string, extra: Partial<JobRecord>,
): JobRecord {
  const job: JobRecord = {
    id: `mh_job_${kind}_${state.jobs.length + 1}_${Math.random().toString(16).slice(2, 8)}`,
    kind,
    tenantId,
    status: 'queued',
    createdAt: Date.now(),
    readyAt: Date.now() + state.profile.asyncLatencyMs,
    runId,
    processed: false,
    ...extra,
  }
  state.jobs.push(job)
  return job
}

async function processJob(state: LabState, job: JobRecord, egress: Egress): Promise<void> {
  if (job.processed || job.status !== 'queued') return
  if (Date.now() < job.readyAt) return
  job.processed = true
  if (job.kind === 'export') {
    job.status = 'ready'
    return
  }
  if (!rawFooterJobs.has(job)) {
    job.trace = 'pdf rendered cleanly'
    job.status = 'ready'
    return
  }
  const response = await egress.fetch('vault.internal', '/internal/render-hook', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-guardian-run-id': job.runId },
    body: JSON.stringify({ invoiceId: job.invoiceId, templateId: job.templateId, runId: job.runId }),
  })
  const text = await response.text()
  let detail = text
  try {
    const parsed = JSON.parse(text) as { detail?: string }
    detail = parsed.detail ?? text
  } catch {
    detail = text
  }
  job.trace = detail
  job.status = response.ok ? 'ready' : 'failed'
}

export async function handleWorker(
  req: IncomingMessage, res: ServerResponse, state: LabState, egress: Egress,
): Promise<void> {
  const url = parseUrl(req)
  const method = req.method ?? 'GET'
  const runId = runIdOf(req, state.runId)

  if (match(url, method, '/health')) {
    sendJson(res, 200, { service: 'worker', ok: true, latencyMs: state.profile.asyncLatencyMs })
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
    sendJson(res, 200, { jobs: state.jobs })
    return
  }

  if (method === 'POST' && match(url, method, '/jobs/export')) {
    const body = parseJson<{ tenantId?: TenantKey; userId?: string; fileName?: string; runId?: string }>(await readBody(req))
    if (!body?.tenantId) {
      sendJson(res, 400, { error: 'tenantId required' })
      return
    }
    const fileName = body.fileName ?? 'treasury.csv'
    const job = newJob(state, 'export', body.tenantId, body.runId ?? runId, { artifactKey: fileName })
    state.emit('worker.job_created', {
      jobId: job.id, kind: 'export', tenantId: job.tenantId, artifactKey: fileName,
      userId: body.userId ?? '', runId: job.runId,
    })
    sendJson(res, 202, { jobId: job.id, status: job.status })
    return
  }

  if (method === 'POST' && match(url, method, '/jobs/render')) {
    const body = parseJson<{
      invoiceId?: string; templateId?: string; tenantId?: TenantKey; footer?: string; rawStored?: boolean; runId?: string
    }>(await readBody(req))
    if (!body?.tenantId || !body.invoiceId || !body.templateId) {
      sendJson(res, 400, { error: 'invoiceId, templateId and tenantId required' })
      return
    }
    const job = newJob(state, 'pdf', body.tenantId, body.runId ?? runId, {
      invoiceId: body.invoiceId,
      templateId: body.templateId,
      artifactKey: `invoice-${body.invoiceId}.pdf`,
    })
    const template = state.templates.find((item) => item.id === body.templateId && item.tenantId === body.tenantId)
    const rawStored = typeof body.rawStored === 'boolean' ? body.rawStored : Boolean(template?.rawStored)
    if (rawStored) rawFooterJobs.add(job)
    state.emit('worker.job_created', {
      jobId: job.id, kind: 'pdf', tenantId: job.tenantId, templateId: body.templateId,
      invoiceId: body.invoiceId, footerLength: (body.footer ?? '').length, runId: job.runId,
    })
    sendJson(res, 202, { jobId: job.id, status: job.status })
    return
  }

  const jobById = match(url, method, '/jobs/:id')
  if (jobById) {
    const job = state.jobs.find((item) => item.id === jobById[0])
    if (!job) {
      sendJson(res, 404, { error: 'unknown job' })
      return
    }
    await processJob(state, job, egress)
    state.emit('worker.job_polled', {
      jobId: job.id, kind: job.kind, status: job.status,
      artifactKey: job.artifactKey ?? '', runId: job.runId,
    })
    sendJson(res, 200, { job })
    return
  }

  const trace = match(url, method, '/jobs/:id/trace')
  if (trace) {
    const job = state.jobs.find((item) => item.id === trace[0])
    if (!job) {
      sendJson(res, 404, { error: 'unknown job' })
      return
    }
    await processJob(state, job, egress)
    const text = job.trace ?? ''
    const leaked = SALT_PATTERN.exec(text)?.[0] ?? ''
    state.emit('worker.job_trace', {
      jobId: job.id, kind: job.kind, status: job.status,
      leakedSecret: leaked, traceSafe: leaked.length === 0, runId: job.runId,
    })
    sendJson(res, 200, { jobId: job.id, status: job.status, trace: text, leakedSecret: leaked || undefined })
    return
  }

  const result = match(url, method, '/jobs/:id/result')
  if (result) {
    const job = state.jobs.find((item) => item.id === result[0])
    if (!job) {
      sendJson(res, 404, { error: 'unknown job' })
      return
    }
    await processJob(state, job, egress)
    sendJson(res, 200, { jobId: job.id, artifactKey: job.artifactKey, status: job.status })
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
    sendJson(res, 200, { queues: ['pdf', 'export', 'webhook'] })
    return
  }
  if (match(url, method, '/webhook-deliveries')) {
    sendJson(res, 200, { deliveries: [] })
    return
  }
  if (match(url, method, '/audit')) {
    sendJson(res, 200, { events: state.audit.slice(-50).map((event) => ({ kind: event.kind, ts: event.ts })) })
    return
  }

  sendJson(res, 404, { error: 'not found', service: 'worker' })
}
