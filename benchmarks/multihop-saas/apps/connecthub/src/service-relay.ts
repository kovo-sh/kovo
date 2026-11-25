// Webhook relay: subscription delivery jobs with seeded jitter and stale callback replay.
import type { IncomingMessage, ServerResponse } from 'node:http'
import { parseJson, readBody, runIdOf, sendJson, match, parseUrl } from './http.ts'
import type { DeliveryRecord, LabState } from './shared.ts'
import { digest, hmac, randomToken } from './policy.ts'
import { installationByCallbackTokenId, seededJitter } from './state.ts'

function processDelivery(state: LabState, job: DeliveryRecord): void {
  if (job.processed || job.status !== 'queued') return
  if (Date.now() < job.readyAt) return
  job.processed = true
  job.status = 'ready'
}

export async function handleRelay(req: IncomingMessage, res: ServerResponse, state: LabState): Promise<void> {
  const url = parseUrl(req)
  const method = req.method ?? 'GET'
  const runId = runIdOf(req, state.runId)

  if (match(url, method, '/health')) {
    sendJson(res, 200, { service: 'webhook-relay', ok: true, latencyMs: state.profile.asyncLatencyMs })
    return
  }
  if (match(url, method, '/metrics')) {
    sendJson(res, 200, {
      webhooks: state.webhooks.length,
      deliveries: state.deliveries.length,
      queued: state.deliveries.filter((job) => job.status === 'queued').length,
      ready: state.deliveries.filter((job) => job.status === 'ready').length,
    })
    return
  }

  if (method === 'POST' && match(url, method, '/subscriptions')) {
    const body = parseJson<{
      webhookId?: string; tenantId?: string; url?: string; secret?: string;
      scopeOmitted?: boolean; events?: string[]; runId?: string
    }>(await readBody(req))
    if (!body?.webhookId || !body.tenantId || !body.secret) {
      sendJson(res, 400, { error: 'webhookId, tenantId and secret required' })
      return
    }
    const scope = (body.events ?? ['app.updated']).join(',')
    const payload = JSON.stringify({
      id: `mh_evt_${state.seq}`,
      event: body.events?.[0] ?? 'app.updated',
      tenant: body.tenantId,
      resource: `mh_res_${state.deliveries.length + 1}`,
    })
    const signature = body.scopeOmitted
      ? hmac(body.secret, payload)
      : hmac(body.secret, `${body.tenantId}:${scope}:${payload}`)
    const job: DeliveryRecord = {
      id: randomToken('mh_dlv_', 8),
      kind: 'delivery',
      webhookId: body.webhookId,
      tenantId: body.tenantId as DeliveryRecord['tenantId'],
      status: 'queued',
      createdAt: Date.now(),
      readyAt: Date.now() + state.profile.asyncLatencyMs + seededJitter(state.plan, body.webhookId),
      body: payload,
      signature,
      scope,
      processed: false,
      runId: body.runId ?? runId,
    }
    state.deliveries.push(job)
    state.emit('relay.delivery_queued', {
      deliveryId: job.id, webhookId: job.webhookId, tenantId: job.tenantId,
      scopeOmitted: body.scopeOmitted === true, runId: job.runId,
    })
    sendJson(res, 201, { deliveryId: job.id, status: job.status })
    return
  }

  const deliveryById = match(url, method, '/deliveries/:id')
  if (deliveryById) {
    const job = state.deliveries.find((item) => item.id === deliveryById[0] && item.kind === 'delivery')
    if (!job) {
      sendJson(res, 404, { error: 'unknown delivery' })
      return
    }
    processDelivery(state, job)
    state.emit('relay.delivery_polled', {
      deliveryId: job.id, webhookId: job.webhookId, tenantId: job.tenantId,
      status: job.status, signature: job.signature, payload: job.body, scope: job.scope,
      runId: job.runId,
    })
    sendJson(res, 200, {
      delivery: {
        id: job.id, status: job.status, tenantId: job.tenantId,
        body: job.body, signature: job.signature, scope: job.scope,
      },
    })
    return
  }

  if (match(url, method, '/deliveries')) {
    sendJson(res, 200, {
      deliveries: state.deliveries.map((job) => ({
        id: job.id, kind: job.kind, status: job.status, tenantId: job.tenantId, scope: job.scope,
      })),
    })
    return
  }

  if (match(url, method, '/subscriptions')) {
    sendJson(res, 200, {
      subscriptions: state.webhooks.map((webhook) => ({
        id: webhook.id, tenantId: webhook.tenantId, url: webhook.url, revoked: webhook.revoked,
      })),
    })
    return
  }

  const webhookDelete = match(url, method, '/webhooks/:id')
  if (webhookDelete) {
    const webhook = state.webhooks.find((item) => item.id === webhookDelete[0])
    if (webhook) webhook.revoked = true
    sendJson(res, 200, { ok: true, revoked: Boolean(webhook) })
    return
  }

  const callbackReplay = match(url, method, '/callbacks/:tokenId/replay')
  if (callbackReplay) {
    const installation = installationByCallbackTokenId(state, callbackReplay[0]!)
    if (!installation || (installation.status === 'uninstalled' && !installation.staleTokenRetained)) {
      state.emit('relay.callback_denied', {
        callbackTokenDigest: digest(callbackReplay[0]!), reason: 'callback_token_revoked', runId,
      })
      sendJson(res, 403, { error: 'callback token is not active' })
      return
    }
    const job: DeliveryRecord = {
      id: randomToken('mh_cbjob_', 8),
      kind: 'callback',
      webhookId: '',
      tenantId: installation.tenantId,
      callbackTokenId: installation.callbackTokenId,
      status: 'queued',
      createdAt: Date.now(),
      readyAt: Date.now() + state.profile.asyncLatencyMs +
        seededJitter(state.plan, installation.callbackTokenId),
      body: '',
      signature: '',
      scope: 'callback',
      processed: false,
      runId,
    }
    state.deliveries.push(job)
    state.emit('relay.callback_replayed', {
      callbackTokenId: installation.callbackTokenId,
      callbackTokenDigest: digest(installation.callbackTokenId),
      jobId: job.id,
      jobDigest: digest(job.id),
      tenantId: installation.tenantId,
      runId,
    })
    sendJson(res, 202, { jobId: job.id, status: job.status })
    return
  }

  const callbackJob = match(url, method, '/callbacks/jobs/:id')
  if (callbackJob) {
    const job = state.deliveries.find((item) => item.id === callbackJob[0] && item.kind === 'callback')
    if (!job) {
      sendJson(res, 404, { error: 'unknown callback job' })
      return
    }
    processDelivery(state, job)
    state.emit('relay.callback_job_polled', {
      jobId: job.id, status: job.status, tenantId: job.tenantId, runId: job.runId,
    })
    sendJson(res, 200, { job: { id: job.id, status: job.status, tenantId: job.tenantId } })
    return
  }

  const cancel = match(url, method, '/jobs/:id/cancel')
  if (cancel) {
    const job = state.deliveries.find((item) => item.id === cancel[0])
    if (job) job.status = 'cancelled'
    sendJson(res, 200, { ok: true })
    return
  }

  if (match(url, method, '/queues')) {
    sendJson(res, 200, {
      queues: [
        { name: 'deliveries', pending: state.deliveries.filter((job) => job.kind === 'delivery').length },
        { name: 'callbacks', pending: state.deliveries.filter((job) => job.kind === 'callback').length },
      ],
    })
    return
  }

  if (match(url, method, '/attempts')) {
    sendJson(res, 200, { attempts: state.deliveries.slice(-20).map((job) => ({ id: job.id, status: job.status })) })
    return
  }

  sendJson(res, 404, { error: 'not found', service: 'webhook-relay' })
}
