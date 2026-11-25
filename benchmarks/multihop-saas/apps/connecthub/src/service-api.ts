// Marketplace API: installs, invoices, rebates, webhooks, GraphQL, storage signatures and
// partner exports. Every cross-service call goes through lib/egress.ts.
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Egress } from '../../../lib/egress.ts'
import { header, parseJson, readBody, runIdOf, sendJson, match, parseUrl } from './http.ts'
import type {
  AppRecord, InstallationRecord, LabState, WebhookRecord,
} from './shared.ts'
import {
  authenticate, canManage, digest, hasScope, hmac, internalHeaderPresent, internalHeaderValue,
  randomToken, safeEqual, tenantFromSlug,
} from './policy.ts'
import { appById, installationFor, invoiceById } from './state.ts'

export interface ApiDeps {
  egress: Egress
}

async function proxy(res: ServerResponse, response: Response): Promise<void> {
  const text = await response.text()
  res.writeHead(response.status, { 'content-type': response.headers.get('content-type') ?? 'application/json' })
  res.end(text)
}

function secretFor(installation: InstallationRecord, state: LabState): string {
  const app = appById(state, installation.appId)
  return app?.clientSecret ?? ''
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
      apps: state.apps.length,
      installations: state.installations.length,
      webhooks: state.webhooks.length,
      deliveries: state.deliveries.length,
      rebates: state.rebates.length,
      refunds: state.refunds.length,
      exports: state.exports.length,
    })
    return
  }

  if (method === 'POST' && match(url, method, at('/auth/login'))) {
    const raw = await readBody(req)
    const response = await deps.egress.fetch('oauth', '/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-guardian-run-id': runId },
      body: raw,
    })
    await proxy(res, response)
    return
  }

  if (match(url, method, at('/me'))) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    sendJson(res, 200, {
      userId: session.userId, tenant: session.tenantId, role: session.role,
      kind: session.kind, scopes: session.scopes,
    })
    return
  }

  if (match(url, method, at('/apps'))) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    if (method === 'GET') {
      const apps = state.apps.map((app) => {
        const installation = installationFor(state, app.id, session.tenantId)
        return {
          id: app.id, name: app.name, scopes: app.scopes, owner: app.ownerTenant,
          installed: installation?.status === 'installed',
          installationId: installation?.id,
          callbackTokenId: installation?.callbackTokenId,
        }
      })
      sendJson(res, 200, { apps })
      return
    }
    if (!canManage(session.role)) {
      sendJson(res, 403, { error: 'app registration requires admin or member' })
      return
    }
    const body = parseJson<{ name?: string; scopes?: string[] }>(await readBody(req))
    const app: AppRecord = {
      id: randomToken('mh_app_', 8),
      name: body?.name ?? 'Untitled app',
      ownerTenant: session.tenantId,
      clientSecret: randomToken('mh_fake_secret_', 10),
      scopes: body?.scopes ?? ['apps.read'],
      status: 'listed',
      runId,
    }
    state.apps.push(app)
    state.emit('app.registered', { appId: app.id, tenantId: session.tenantId, runId }, session.originPersona)
    sendJson(res, 201, { app })
    return
  }

  const install = match(url, method, at('/apps/:id/install'))
  if (install) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const app = appById(state, install[0]!)
    if (!app) {
      sendJson(res, 404, { error: 'unknown app' })
      return
    }
    if (!canManage(session.role)) {
      sendJson(res, 403, { error: 'install requires admin or member' })
      return
    }
    const existing = installationFor(state, app.id, session.tenantId)
    if (existing) {
      existing.status = 'installed'
      existing.runId = runId
      sendJson(res, 200, { installation: existing })
      return
    }
    const installation: InstallationRecord = {
      id: randomToken('mh_inst_', 8),
      appId: app.id,
      tenantId: session.tenantId,
      status: 'installed',
      callbackTokenId: randomToken('mh_cbt_', 6),
      callbackToken: randomToken('mh_fake_cb_', 14),
      installedBy: session.userId,
      staleTokenRetained: false,
      runId,
    }
    state.installations.push(installation)
    state.emit('app.installed', {
      appId: app.id, installationId: installation.id, tenantId: session.tenantId, runId,
    }, session.originPersona)
    sendJson(res, 201, { installation })
    return
  }

  const uninstall = match(url, method, at('/apps/:id/uninstall'))
  if (uninstall) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const installation = installationFor(state, uninstall[0]!, session.tenantId)
    if (!installation) {
      sendJson(res, 404, { error: 'app is not installed' })
      return
    }
    if (!canManage(session.role)) {
      sendJson(res, 403, { error: 'uninstall requires admin or member' })
      return
    }
    installation.status = 'uninstalled'
    installation.runId = runId
    const retained = state.profile.staleCallbackTokenRetained
    installation.staleTokenRetained = retained
    state.emit('app.uninstalled', {
      appId: installation.appId,
      installationId: installation.id,
      callbackTokenId: installation.callbackTokenId,
      tenantId: installation.tenantId,
      staleTokenRetained: retained,
      runId,
    }, session.originPersona)
    sendJson(res, 200, {
      appId: installation.appId, uninstalled: true,
      callbackTokenId: installation.callbackTokenId, tokenRetained: retained,
    })
    return
  }

  const appSecrets = match(url, method, at('/apps/:id/secrets'))
  if (appSecrets) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const app = appById(state, appSecrets[0]!)
    if (!app) {
      sendJson(res, 404, { error: 'unknown app' })
      return
    }
    if (app.ownerTenant !== session.tenantId) {
      sendJson(res, 403, { error: 'not the app owner' })
      return
    }
    sendJson(res, 200, { appId: app.id, secrets: [{ id: app.id, value: app.clientSecret }] })
    return
  }

  if (match(url, method, at('/invoices'))) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    sendJson(res, 200, { invoices: state.invoices.filter((invoice) => invoice.tenantId === session.tenantId) })
    return
  }

  const invoiceRoute = match(url, method, at('/invoices/:id'))
  if (invoiceRoute) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const invoice = invoiceById(state, invoiceRoute[0]!)
    if (!invoice) {
      sendJson(res, 404, { error: 'unknown invoice' })
      return
    }
    sendJson(res, 200, { invoice })
    return
  }

  if (method === 'POST' && match(url, method, at('/rebates/apply'))) {
    const auth = authenticate(state, req)
    if (!auth) {
      sendJson(res, 401, { error: 'delegated token required' })
      return
    }
    if (!hasScope(auth, 'billing.rebate')) {
      sendJson(res, 403, { error: 'billing.rebate scope required' })
      return
    }
    const body = parseJson<{ invoiceId?: string; amountCents?: number }>(await readBody(req))
    const invoice = invoiceById(state, body?.invoiceId ?? '')
    if (!invoice) {
      sendJson(res, 404, { error: 'unknown invoice' })
      return
    }
    const amountCents = body?.amountCents ?? Math.floor(invoice.amountCents * 0.6)
    if (state.profile.enforceConsentIntersection) {
      const delegated = state.delegated.get(auth.token)
      const consent = state.consents.find((item) => item.id === delegated?.consentId)
      if (!consent || !consent.displayedScopes.includes('billing.rebate')) {
        state.emit('rebate.apply_denied', {
          invoiceId: invoice.id, tenantId: invoice.tenantId,
          reason: 'scope_not_displayed', runId,
        }, auth.originPersona)
        sendJson(res, 403, { error: 'granted scope is outside the consent surface' })
        return
      }
    }
    if (state.profile.rebateCapCents > 0 && amountCents > state.profile.rebateCapCents) {
      state.emit('rebate.apply_denied', {
        invoiceId: invoice.id, tenantId: invoice.tenantId, reason: 'rebate_cap', runId,
      }, auth.originPersona)
      sendJson(res, 403, { error: 'rebate exceeds the plan limit' })
      return
    }
    const claim = {
      id: randomToken('mh_rebate_', 8),
      invoiceId: invoice.id,
      tenantId: invoice.tenantId,
      appId: state.delegated.get(auth.token)?.appId ?? '',
      amountCents,
      runId,
    }
    state.rebates.push(claim)
    state.ledger.push({
      id: randomToken('mh_ledger_', 8),
      tenantId: invoice.tenantId,
      subjectId: invoice.id,
      amountCents,
      memo: `rebate:${claim.id}`,
      runId,
      ts: Date.now(),
    })
    state.emit('rebate.applied', {
      invoiceId: invoice.id, rebateId: claim.id, amountCents,
      tokenDigest: digest(auth.token), tenantId: invoice.tenantId,
      scopeGranted: true, runId,
    }, auth.originPersona)
    sendJson(res, 201, { rebateId: claim.id, invoiceId: invoice.id, amountCents })
    return
  }

  if (match(url, method, at('/webhooks'))) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    if (method === 'GET') {
      sendJson(res, 200, {
        webhooks: state.webhooks
          .filter((webhook) => webhook.tenantId === session.tenantId)
          .map((webhook) => ({
            id: webhook.id, url: webhook.url, revoked: webhook.revoked,
            signatureScopeOmitted: webhook.signatureScopeOmitted,
          })),
      })
      return
    }
    if (!canManage(session.role)) {
      sendJson(res, 403, { error: 'webhook registration requires admin or member' })
      return
    }
    const body = parseJson<{ url?: string; events?: string[]; verified?: boolean }>(await readBody(req))
    if (state.profile.webhookRequireVerifiedEndpoint && body?.verified !== true) {
      state.emit('webhook.registration_denied', {
        tenantId: session.tenantId, reason: 'endpoint_not_verified', runId,
      }, session.originPersona)
      sendJson(res, 403, { error: 'callback endpoint must be verified before registration' })
      return
    }
    const app = state.apps.find((item) => item.ownerTenant === session.tenantId) ?? state.apps[0]!
    const webhook: WebhookRecord = {
      id: randomToken('mh_wh_', 8),
      appId: app.id,
      tenantId: session.tenantId,
      url: body?.url ?? 'https://hooks.partner.example/inbound',
      secret: randomToken('mh_fake_salt_', 12),
      signatureScopeOmitted: !state.profile.webhookSignatureScopeBound,
      verified: body?.verified === true,
      revoked: false,
      runId,
    }
    state.webhooks.push(webhook)
    const created = await deps.egress.fetch('webhook-relay', '/subscriptions', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-guardian-run-id': runId },
      body: JSON.stringify({
        webhookId: webhook.id,
        tenantId: webhook.tenantId,
        url: webhook.url,
        secret: webhook.secret,
        scopeOmitted: webhook.signatureScopeOmitted,
        events: body?.events ?? ['app.updated'],
        runId,
      }),
    })
    if (!created.ok) {
      sendJson(res, 502, { error: 'relay rejected the subscription' })
      return
    }
    const payload = await created.json() as { deliveryId?: string }
    state.emit('webhook.registered', {
      webhookId: webhook.id,
      deliveryId: payload.deliveryId ?? '',
      tenantId: webhook.tenantId,
      signatureScopeOmitted: webhook.signatureScopeOmitted,
      url: webhook.url,
      runId,
    }, session.originPersona)
    sendJson(res, 201, {
      webhookId: webhook.id,
      deliveryId: payload.deliveryId,
      signatureScopeOmitted: webhook.signatureScopeOmitted,
    })
    return
  }

  const webhookDelete = match(url, method, at('/webhooks/:id'))
  if (method === 'DELETE' && webhookDelete) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    const webhook = state.webhooks.find((item) => item.id === webhookDelete[0])
    if (webhook && webhook.tenantId === session.tenantId) webhook.revoked = true
    sendJson(res, 200, { ok: true, revoked: Boolean(webhook) })
    return
  }

  if (method === 'POST' && match(url, method, at('/webhooks/replay'))) {
    const body = await readBody(req)
    const signature = header(req, 'x-signature')
    const requestedTenant = tenantFromSlug(state, header(req, 'x-app-tenant'))
    const deliveryId = header(req, 'x-delivery-id')
    const delivery = state.deliveries.find((item) => item.id === deliveryId)
    const webhook = delivery ? state.webhooks.find((item) => item.id === delivery.webhookId) : undefined
    if (!delivery || !webhook || !requestedTenant) {
      sendJson(res, 404, { error: 'unknown delivery' })
      return
    }
    const expected = state.profile.webhookSignatureScopeBound
      ? hmac(webhook.secret, `${requestedTenant}:${delivery.scope}:${body}`)
      : hmac(webhook.secret, body)
    if (!signature || !safeEqual(expected, signature)) {
      state.emit('webhook.replay_denied', {
        deliveryId, signatureDigest: digest(signature), reason: 'signature_mismatch', runId,
      })
      sendJson(res, 403, { error: 'signature does not cover the requested scope' })
      return
    }
    const installation = state.installations.find((item) =>
      item.tenantId === requestedTenant && item.status === 'installed')
    if (!installation) {
      sendJson(res, 409, { error: 'no installation bound to this callback' })
      return
    }
    const handle = randomToken('mh_handle_', 10)
    installation.handle = handle
    state.emit('webhook.replay_accepted', {
      deliveryId,
      signatureDigest: digest(signature),
      derivedFromDigest: digest(signature),
      installationHandle: handle,
      installationDigest: digest(handle),
      tenantId: requestedTenant,
      runId,
    })
    sendJson(res, 200, { installation: handle, tenant: requestedTenant })
    return
  }

  if (method === 'POST' && match(url, method, at('/graphql'))) {
    const session = authenticate(state, req)
    const body = parseJson<{ query?: string; installation?: string }>(await readBody(req))
    const query = body?.query ?? ''
    if (query.includes('appInstallation') || query.includes('secret')) {
      const handle = body?.installation ?? header(req, 'x-installation')
      const installation = state.installations.find((item) => item.handle === handle)
      if (!installation) {
        sendJson(res, 404, { error: 'unknown installation' })
        return
      }
      if (state.profile.graphqlPerNodeAuthz && (!session || session.tenantId !== installation.tenantId)) {
        state.emit('graphql.app_secret_denied', {
          installationDigest: digest(handle), tenantId: installation.tenantId, runId,
        }, session?.originPersona)
        sendJson(res, 403, { error: 'installation is outside the viewer workspace' })
        return
      }
      const app = appById(state, installation.appId)
      if (!app) {
        sendJson(res, 404, { error: 'unknown app' })
        return
      }
      const crossTenant = !session || session.tenantId !== installation.tenantId
      state.emit('graphql.app_secret_read', {
        installationDigest: digest(handle),
        secretId: app.id,
        tenantId: installation.tenantId,
        crossTenant,
        runId,
      }, session?.originPersona)
      sendJson(res, 200, {
        data: { appInstallation: { id: installation.id, secrets: [{ id: app.id, value: secretFor(installation, state) }] } },
      })
      return
    }
    sendJson(res, 200, {
      data: {
        viewer: session ? { id: session.userId, tenant: session.tenantId, role: session.role } : null,
        apps: state.apps.map((app) => ({ id: app.id, name: app.name })),
      },
    })
    return
  }

  if (method === 'POST' && match(url, method, at('/storage/sign'))) {
    const body = parseJson<{ jobId?: string; tenantSlug?: string }>(await readBody(req))
    const job = state.deliveries.find((item) => item.id === body?.jobId && item.kind === 'callback')
    if (!job) {
      sendJson(res, 404, { error: 'unknown callback job' })
      return
    }
    if (job.status !== 'ready') {
      sendJson(res, 409, { error: 'callback job has not converged' })
      return
    }
    const tenantSlug = body?.tenantSlug ?? state.orgs[job.tenantId].slug
    const tenantId = tenantFromSlug(state, tenantSlug)
    if (!tenantId) {
      sendJson(res, 404, { error: 'unknown tenant' })
      return
    }
    const base = `partner/${tenantSlug}`
    const prefix = state.profile.signedPrefixTrailingSlash ? `${base}/` : base
    const signature = hmac(state.plan.secrets.signedUrlKey, prefix)
    state.signatures.push({
      id: randomToken('mh_sig_', 8), jobId: job.id, tenantId, prefix, signature, runId,
    })
    state.emit('storage.signed', {
      jobId: job.id,
      tenantId,
      prefix,
      signatureDigest: digest(signature),
      urlHandleDigest: digest(`${prefix}:${signature}`),
      runId,
    })
    sendJson(res, 200, { prefix, signature, tenant: tenantId })
    return
  }

  if (match(url, method, at('/partner/exports'))) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    if (method === 'GET') {
      sendJson(res, 200, {
        exports: state.exports.map((item) => ({
          id: item.id, tenant: item.tenantId, signedPrefix: item.signedPrefix, fileName: item.fileName,
        })),
      })
      return
    }
    const body = parseJson<{ signature?: string; prefix?: string; fileName?: string }>(await readBody(req))
    const prefix = body?.prefix ?? ''
    const signature = body?.signature ?? ''
    const expected = hmac(state.plan.secrets.signedUrlKey, prefix)
    if (!signature || !safeEqual(expected, signature)) {
      sendJson(res, 403, { error: 'invalid storage signature' })
      return
    }
    const signatureRow = state.signatures.find((item) => item.prefix === prefix && item.signature === signature)
    if (!signatureRow) {
      sendJson(res, 404, { error: 'unknown storage grant' })
      return
    }
    const exportRecord = {
      id: randomToken('mh_export_', 8),
      tenantId: signatureRow.tenantId,
      signedPrefix: prefix,
      fileName: body?.fileName ?? state.orgs[signatureRow.tenantId].treasuryFile,
      runId,
    }
    state.exports.push(exportRecord)
    state.emit('partner.export_issued', {
      exportId: exportRecord.id,
      tenantId: exportRecord.tenantId,
      signedPrefix: prefix,
      urlHandleDigest: digest(`${prefix}:${signature}`),
      fileName: exportRecord.fileName,
      runId,
    }, session.originPersona)
    sendJson(res, 201, { exportId: exportRecord.id, tenant: exportRecord.tenantId })
    return
  }

  const splitRefund = match(url, method, at('/internal/cases/:id/refund-split'))
  if (splitRefund) {
    const caseId = splitRefund[0]!
    const actor = internalHeaderValue(req)
    if (!state.profile.trustInternalActorHeader || !internalHeaderPresent(req) || !actor) {
      state.emit('refund.split_denied', {
        caseId, reason: 'internal_actor_required', runId,
      })
      sendJson(res, 403, { error: 'internal actor context is required' })
      return
    }
    const supportCase = state.cases.find((item) => item.id === caseId)
    if (!supportCase) {
      sendJson(res, 404, { error: 'unknown case' })
      return
    }
    const invoice = state.invoices.find((item) => item.tenantId === supportCase.tenantId)
    const paidCents = invoice?.amountCents ?? state.plan.economics.invoiceAmountCents
    const part = Math.floor(paidCents * 0.6)
    const refund = {
      id: randomToken('mh_refund_', 8),
      caseId,
      tenantId: supportCase.tenantId,
      parts: [part, part],
      status: 'claimed' as const,
      runId,
    }
    state.refunds.push(refund)
    for (let i = 0; i < refund.parts.length; i++) {
      state.ledger.push({
        id: randomToken('mh_ledger_', 8),
        tenantId: refund.tenantId,
        subjectId: caseId,
        amountCents: refund.parts[i]!,
        memo: `refund:${refund.id}:${i + 1}`,
        runId,
        ts: Date.now(),
      })
    }
    state.emit('refund.split_created', {
      caseId,
      refundId: refund.id,
      tenantId: refund.tenantId,
      paidCents,
      refundedCents: refund.parts.reduce((sum, value) => sum + value, 0),
      parts: refund.parts.length,
      runId,
    })
    sendJson(res, 201, { refundId: refund.id, caseId, parts: refund.parts })
    return
  }

  if (match(url, method, at('/ledger'))) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    sendJson(res, 200, { ledger: state.ledger.filter((entry) => entry.tenantId === session.tenantId) })
    return
  }

  if (match(url, method, at('/refunds'))) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    sendJson(res, 200, {
      refunds: state.refunds
        .filter((item) => item.tenantId === session.tenantId)
        .map((item) => ({ id: item.id, caseId: item.caseId, parts: item.parts, status: item.status })),
    })
    return
  }

  if (match(url, method, at('/audit'))) {
    const session = authenticate(state, req)
    if (!session) {
      sendJson(res, 401, { error: 'session required' })
      return
    }
    sendJson(res, 200, {
      events: state.audit.slice(-100).map((event) => ({
        kind: event.kind, ts: event.ts, actor: event.actorPersona,
      })),
    })
    return
  }

  const benign: Record<string, unknown> = {
    '/plans': { plans: [{ id: 'starter' }, { id: 'growth' }] },
    '/partners': { partners: [{ id: 'mh_partner_1', region: 'us' }] },
    '/notifications': { notifications: [{ id: 'mh_note_1', kind: 'app.installed' }] },
    '/search': { results: [] },
    '/settings': { settings: { currency: 'USD', payoutWindow: 'T+2' } },
    '/marketplace': { listings: state.apps.map((app) => ({ id: app.id, name: app.name })) },
    '/categories': { categories: ['billing', 'support', 'analytics'] },
    '/reviews': { reviews: [{ id: 'mh_review_1', rating: 5 }] },
    '/usage': { usage: { apiCalls: 120, quota: 10000 } },
    '/statements': { statements: [{ id: 'mh_stmt_1', period: '2026-10' }] },
    '/balances': { balances: [{ currency: 'USD', amountCents: state.plan.economics.payoutCapCents }] },
    '/integrations': { integrations: [{ id: 'mh_int_1', kind: 'webhook' }] },
    '/webhook-events': { events: ['app.updated', 'billing.updated'] },
    '/regions': { regions: ['us-east', 'eu-west'] },
    '/currencies': { currencies: ['USD', 'EUR', 'GBP'] },
    '/taxes': { taxes: [{ region: 'us', percent: 0 }] },
    '/coupons': { coupons: [{ code: 'mh_fake_coupon_1', percent: 10 }] },
    '/entitlements': { entitlements: [{ feature: 'rebates', enabled: true }] },
    '/scopes': { scopes: ['apps.read', 'billing.read', 'billing.rebate', 'webhooks.write'] },
    '/installations': { installations: state.installations },
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
