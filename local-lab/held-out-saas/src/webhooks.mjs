// Outbound webhooks. Registration (injection) and delivery (sink) are separate requests => second-order SSRF.
import { fetchLoopback, isLoopbackUrl, sendJson } from './http-util.mjs'
import { marker } from './markers.mjs'

/** Delivery agent. Lab egress policy: only loopback / lab-internal origins are ever contacted. */
async function deliver(ctx, hook, event, payload) {
  const started = Date.now()
  const res = await fetchLoopback(hook.url, {
    timeoutMs: 2000,
    maxBytes: 512,
    headers: { 'x-lab-webhook': '1', 'content-type': 'application/json' },
  })
  const record = {
    id: `dlv_${ctx.s.deliveries.length + 1}`,
    hookId: hook.id,
    tenantId: hook.tenantId,
    event,
    status: res.blocked ? 'blocked' : (res.status || 0),
    error: res.error ?? null,
    responseSnippet: res.body.slice(0, 200),
    durationMs: Date.now() - started,
    payload,
  }
  ctx.s.deliveries.push(record)
  if (ctx.s.deliveries.length > 200) ctx.s.deliveries.shift()
  return record
}

export async function fireWebhookEvent(ctx, tenantId, event, payload) {
  const hooks = [...ctx.s.webhooks.values()].filter(h => h.tenantId === tenantId && (h.event === event || h.event === '*'))
  await Promise.all(hooks.map(h => deliver(ctx, h, event, payload)))
}

export function register(router, ctx) {
  // hos-16: the URL is stored after a scheme check only; the delivery agent later fetches it server-side.
  router.post('/api/v1/webhooks', async c => {
    const user = c.requireUser()
    if (!user) return
    const body = await c.json()
    const url = String(body.url ?? '')
    if (!/^https?:\/\//i.test(url)) return sendJson(c.res, 400, { error: 'invalid_url' })
    if (ctx.fixed('hos-16')) {
      let host = ''
      try { host = new URL(url).hostname } catch { /* invalid */ }
      if (host !== 'hooks.partner.example' || isLoopbackUrl(url)) return sendJson(c.res, 400, { error: 'host_not_allowlisted' })
    }
    const id = `wh_${++ctx.s.counters.webhook}`
    const hook = { id, tenantId: user.tenant, url, event: String(body.event ?? 'order.confirmed').slice(0, 40) }
    ctx.s.webhooks.set(id, hook)
    sendJson(c.res, 201, hook)
  })

  router.get('/api/v1/webhooks', c => {
    const user = c.requireUser()
    if (!user) return
    sendJson(c.res, 200, { webhooks: [...ctx.s.webhooks.values()].filter(h => h.tenantId === user.tenant) })
  })

  router.post('/api/v1/webhooks/:id/ping', async c => {
    const user = c.requireUser()
    if (!user) return
    const hook = ctx.s.webhooks.get(c.params.id)
    if (!hook || hook.tenantId !== user.tenant) return sendJson(c.res, 404, { error: 'not_found' })
    const record = await deliver(ctx, hook, 'ping', { ping: true })
    sendJson(c.res, 200, { delivery: record })
  })

  router.get('/api/v1/webhooks/:id/deliveries', c => {
    const user = c.requireUser()
    if (!user) return
    const hook = ctx.s.webhooks.get(c.params.id)
    if (!hook || hook.tenantId !== user.tenant) return sendJson(c.res, 404, { error: 'not_found' })
    sendJson(c.res, 200, { deliveries: ctx.s.deliveries.filter(d => d.hookId === hook.id) })
  })

  // Internal service that trusts the delivery agent header (reachable only via server-side fetches).
  router.get('/internal/webhook-sink', c => {
    if (c.req.headers['x-lab-webhook'] !== '1') return sendJson(c.res, 404, { error: 'not_found' })
    sendJson(c.res, 200, { internal: true, note: `internal sink ${marker('hos-16')}` })
  })
}
