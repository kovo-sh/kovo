// Internal package registry and artifact index. Service-to-service only: the internal bearer token
// gates synchronous tenant metadata sync.
import type { IncomingMessage, ServerResponse } from 'node:http'
import { readBody, parseJson, sendJson, header, runIdOf, match, parseUrl } from './http.ts'
import type { LabState, TenantKey } from './shared.ts'
import { digest, safeEqualText } from './policy.ts'

function tokenAccepted(state: LabState, token: string): boolean {
  return safeEqualText(token, state.plan.secrets.internalBearerToken)
}

/** True only for a webhook delivery the source-control service is dispatching right now. */
function inFlightDelivery(state: LabState, deliveryId: string): boolean {
  if (!deliveryId) return false
  return state.webhooks.some((webhook) =>
    webhook.targetHost === 'registry.internal' && webhook.deliveries.length === 0 &&
    `mh_dlv_${webhook.id}_1` === deliveryId)
}

export async function handleRegistry(
  req: IncomingMessage, res: ServerResponse, state: LabState,
): Promise<void> {
  const url = parseUrl(req)
  const method = req.method ?? 'GET'
  const runId = runIdOf(req, state.runId)

  if (match(url, method, '/health')) {
    sendJson(res, 200, { service: 'registry.internal', ok: true })
    return
  }
  if (match(url, method, '/metrics')) {
    sendJson(res, 200, { packages: 42, tenants: state.distro.length, syncs: state.audit.length })
    return
  }

  if (method === 'POST' && match(url, method, '/sync')) {
    const body = parseJson<{ tenant?: string; projectId?: string }>(await readBody(req))
    const token = header(req, 'x-registry-token')
    if (!tokenAccepted(state, token)) {
      const deliveryId = url.search.get('delivery') ?? ''
      if (state.profile.internalDiagnosticLeak && !state.profile.deliveryLogRedacted &&
        inFlightDelivery(state, deliveryId)) {
        sendJson(res, 500, {
          error: 'sync rejected',
          detail: `service credential missing; expected ${state.plan.secrets.internalBearerToken}`,
          requestId: digest(`${deliveryId}:${runId}`).slice(0, 12),
        })
        return
      }
      state.emit('registry.sync_denied', {
        reason: 'invalid_credential', tokenPresent: token.length > 0, runId,
      })
      sendJson(res, 401, { error: 'registry credential required' })
      return
    }
    if (state.profile.registryTokenScoped) {
      state.emit('registry.sync_denied', { reason: 'token_scope', runId })
      sendJson(res, 403, { error: 'credential is not scoped to this sync' })
      return
    }
    const tenantId = (body?.tenant ? state.distro.find((tenant) => tenant.slug === body.tenant || tenant.id === body.tenant)?.id : null) ??
      (body?.tenant as TenantKey | undefined) ?? null
    if (!tenantId) {
      sendJson(res, 400, { error: 'tenant required' })
      return
    }
    const secrets = state.secrets.filter((secret) => secret.tenantId === tenantId)
    const payload = secrets.map((secret) => ({ name: secret.name, scope: secret.scope, value: secret.value }))
    const text = JSON.stringify(payload)
    state.emit('registry.sync', {
      tenantId,
      projectId: body?.projectId ?? '',
      tokenDigest: digest(token),
      tokenValid: true,
      scoped: false,
      secretCount: payload.length,
      secretDigest: digest(text),
      runId,
    })
    sendJson(res, 200, { tenant: tenantId, secrets: payload })
    return
  }

  // Remaining registry surfaces are service-to-service only.
  if (!tokenAccepted(state, header(req, 'x-registry-token'))) {
    sendJson(res, 401, { error: 'registry credential required' })
    return
  }

  if (match(url, method, '/packages')) {
    sendJson(res, 200, {
      packages: [
        { name: 'shipforge/cli', version: '3.4.1' },
        { name: 'shipforge/runner-image', version: '2026.10' },
      ],
    })
    return
  }
  if (match(url, method, '/index')) {
    sendJson(res, 200, { index: ['artifact', 'package', 'layer'], tenants: state.distro.map((tenant) => tenant.slug) })
    return
  }
  const artifact = match(url, method, '/artifacts/:name')
  if (artifact) {
    sendJson(res, 200, {
      name: artifact[0], digest: digest(`${artifact[0]}:${state.runId}`), retentionDays: 30,
    })
    return
  }
  if (match(url, method, '/policies')) {
    sendJson(res, 200, { policies: ['tenant-scoped-sync', 'artifact-retention', 'signed-layers'] })
    return
  }
  if (match(url, method, '/audit')) {
    sendJson(res, 200, { events: state.audit.slice(-50).map((event) => ({ kind: event.kind, ts: event.ts })) })
    return
  }

  sendJson(res, 404, { error: 'not found', service: 'registry.internal' })
}
