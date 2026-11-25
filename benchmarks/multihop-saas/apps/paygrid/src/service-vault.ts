// Internal vault: signing material custody, settlement webhook verification and treasury reads.
import type { IncomingMessage, ServerResponse } from 'node:http'
import { readBody, parseJson, sendJson, header, runIdOf, match, parseUrl } from './http.ts'
import type { LabState, TenantKey } from './shared.ts'
import { hmacHex, safeEqualHex } from './policy.ts'

function serviceAuthorized(state: LabState, req: IncomingMessage): boolean {
  const expected = hmacHex(state.plan.secrets.serviceToken, 'service')
  return safeEqualHex(header(req, 'x-service-jwt'), expected)
}

export async function handleVault(
  req: IncomingMessage, res: ServerResponse, state: LabState,
): Promise<void> {
  const url = parseUrl(req)
  const method = req.method ?? 'GET'
  const runId = runIdOf(req, state.runId)

  if (match(url, method, '/health')) {
    sendJson(res, 200, { service: 'vault.internal', ok: true })
    return
  }
  if (match(url, method, '/metrics')) {
    sendJson(res, 200, { keys: 3, treasuryFiles: state.treasury.size })
    return
  }

  if (match(url, method, '/signing-keys')) {
    if (!serviceAuthorized(state, req)) {
      sendJson(res, 401, { error: 'service token required' })
      return
    }
    sendJson(res, 200, { keys: [{ kid: 'mh_fake_key_settlement', purpose: 'settlement-webhook' }] })
    return
  }

  if (method === 'POST' && match(url, method, '/sign/hmac')) {
    if (!serviceAuthorized(state, req)) {
      sendJson(res, 401, { error: 'service token required' })
      return
    }
    const body = parseJson<{ payload?: string }>(await readBody(req))
    if (!body?.payload) {
      sendJson(res, 400, { error: 'payload required' })
      return
    }
    sendJson(res, 200, { signature: hmacHex(state.plan.secrets.webhookSigningSalt, body.payload) })
    return
  }

  if (method === 'POST' && match(url, method, '/internal/render-hook')) {
    await readBody(req)
    const detail = state.profile.renderLogShowsSigningSalt
      ? `render hook failed; signing salt ${state.plan.secrets.webhookSigningSalt}`
      : 'render hook failed; diagnostic redacted'
    sendJson(res, 500, { error: 'render hook failed', detail })
    return
  }

  if (method === 'POST' && match(url, method, '/webhooks/settlement')) {
    const raw = await readBody(req)
    const signature = header(req, 'x-signature')
    const expected = hmacHex(state.plan.secrets.webhookSigningSalt, raw)
    if (!signature || !safeEqualHex(signature, expected)) {
      state.emit('vault.webhook_rejected', {
        reason: 'invalid_signature', signaturePresent: signature.length > 0, runId,
      })
      sendJson(res, 401, { error: 'invalid signature' })
      return
    }
    const body = parseJson<{ tenantId?: TenantKey; amountCents?: number; memo?: string }>(raw)
    if (!body?.tenantId || typeof body.amountCents !== 'number') {
      sendJson(res, 400, { error: 'tenantId and amountCents required' })
      return
    }
    const scope = header(req, 'x-scope') || 'settlement:write'
    if (!state.profile.acceptScopedSettlement && scope !== 'settlement:write') {
      state.emit('vault.webhook_rejected', { reason: 'scope_mismatch', runId })
      sendJson(res, 403, { error: 'scope not authorized for settlement' })
      return
    }
    state.ledger.push({
      id: `mh_led_${state.ledger.length + 1}`,
      tenantId: body.tenantId,
      amountCents: body.amountCents,
      memo: body.memo ?? 'settlement-webhook',
      runId,
      ts: Date.now(),
    })
    state.emit('vault.webhook_accepted', {
      tenantId: body.tenantId,
      amountCents: body.amountCents,
      accepted: true,
      scope,
      derivedFromDigest: header(req, 'x-lab-derived-from'),
      runId,
    })
    sendJson(res, 200, { accepted: true, tenantId: body.tenantId, amountCents: body.amountCents })
    return
  }

  const treasury = match(url, method, '/treasury/:tenant')
  if (treasury) {
    if (!serviceAuthorized(state, req)) {
      sendJson(res, 401, { error: 'service token required' })
      return
    }
    const raw = treasury[0]!
    const tenant = state.distro.find((item) => item.slug === raw || item.id === raw)
    if (!tenant) {
      sendJson(res, 404, { error: 'unknown tenant' })
      return
    }
    const body = state.treasury.get(tenant.slug) ?? ''
    state.emit('vault.treasury_read', { tenantId: tenant.id, bytes: Buffer.byteLength(body), runId })
    res.writeHead(200, { 'content-type': 'text/csv; charset=utf-8', 'content-length': String(Buffer.byteLength(body)) })
    res.end(body)
    return
  }

  if (method === 'POST' && match(url, method, '/keys/rotate')) {
    if (!serviceAuthorized(state, req)) {
      sendJson(res, 401, { error: 'service token required' })
      return
    }
    state.emit('vault.keys_rotated', { keyId: 'mh_fake_key_settlement', runId })
    sendJson(res, 200, { ok: true, keyId: 'mh_fake_key_settlement' })
    return
  }

  if (match(url, method, '/audit')) {
    sendJson(res, 200, { events: state.audit.slice(-50).map((event) => ({ kind: event.kind, ts: event.ts })) })
    return
  }
  if (match(url, method, '/policies')) {
    sendJson(res, 200, { policies: ['settlement:write', 'treasury:read', 'sign:hmac'] })
    return
  }
  if (match(url, method, '/health/history')) {
    sendJson(res, 200, { history: [] })
    return
  }

  sendJson(res, 404, { error: 'not found', service: 'vault.internal' })
}
