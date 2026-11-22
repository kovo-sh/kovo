// Application wiring: context, response cache layer (edge-style), request dispatch.
import { CACHE_TTL_MS, CACHEABLE_EXT_RE, PATCH_STATE } from './config.mjs'
import { personaToken, tokenFromRequest, verifyStrict } from './auth.mjs'
import { httpError, readBody, sendJson } from './http-util.mjs'
import { createRouter } from './router.mjs'
import { USERS, createState } from './state.mjs'
import { register as registerPages } from './pages.mjs'
import { register as registerIdentity } from './identity.mjs'
import { register as registerBilling } from './billing.mjs'
import { register as registerContent } from './content.mjs'
import { register as registerFiles } from './files.mjs'
import { register as registerGraphql } from './graphql.mjs'
import { register as registerXml } from './xml-import.mjs'
import { register as registerWebhooks } from './webhooks.mjs'
import { register as registerActions } from './routes-actions.mjs'
import { register as registerDecoys } from './decoys.mjs'

export const PATCH_IDS = Object.keys(PATCH_STATE)

export function createApp(options = {}) {
  const ctx = {
    s: createState(),
    patched: new Set(options.patchedIds ?? []),
    fixed(id) {
      return PATCH_STATE[id] === true || ctx.patched.has(id)
    },
    reset() {
      try { ctx.s.db.close() } catch { /* already closed */ }
      ctx.s = createState()
    },
  }

  const router = createRouter()
  registerPages(router, ctx)
  registerIdentity(router, ctx)
  registerBilling(router, ctx)
  registerContent(router, ctx)
  registerFiles(router, ctx)
  registerGraphql(router, ctx)
  registerXml(router, ctx)
  registerWebhooks(router, ctx)
  registerActions(router, ctx)
  registerDecoys(router, ctx)

  async function handle(req, res) {
    const method = req.method ?? 'GET'
    let url
    try {
      url = new URL(req.url ?? '/', 'http://orbit.lab')
    } catch {
      return sendJson(res, 400, { error: 'bad_request' })
    }
    res.setHeader('x-powered-by', 'Next.js')

    // Edge cache: keyed on the full URL (incl. query) and — by design — NOT on identity.
    if (method === 'GET' && CACHEABLE_EXT_RE.test(url.pathname)) {
      const key = url.pathname + url.search
      const hit = ctx.s.cache.get(key)
      if (hit && Date.now() - hit.at < CACHE_TTL_MS) {
        res.writeHead(hit.status, { ...hit.headers, 'x-cache': 'HIT', age: String(Math.max(1, Math.floor((Date.now() - hit.at) / 1000))) })
        return res.end(hit.body)
      }
      res.cacheCapture = (status, headers, body) => {
        headers['x-cache'] = 'MISS'
        if (status !== 200 || /no-store|private/i.test(String(headers['cache-control'] ?? ''))) return
        if (ctx.s.cache.size >= 200) ctx.s.cache.delete(ctx.s.cache.keys().next().value)
        ctx.s.cache.set(key, { status, headers: { ...headers }, body, at: Date.now() })
      }
    }

    const matched = router.match(method, url.pathname)
    if (!matched) return sendJson(res, 404, { error: 'not_found', path: url.pathname })
    if (matched.methodNotAllowed) return sendJson(res, 405, { error: 'method_not_allowed' })

    let bodyText
    const c = {
      req,
      res,
      url,
      ctx,
      params: matched.params,
      query: Object.fromEntries(url.searchParams),
      user() {
        return verifyStrict(tokenFromRequest(req))
      },
      requireUser() {
        const user = c.user()
        if (!user) sendJson(res, 401, { error: 'unauthorized' }, { 'www-authenticate': 'Bearer realm="orbit"' })
        return user
      },
      async text() {
        bodyText ??= await readBody(req)
        return bodyText
      },
      async json() {
        const raw = await c.text()
        try {
          return raw ? JSON.parse(raw) : {}
        } catch {
          throw httpError(400, 'invalid json body')
        }
      },
    }

    try {
      await matched.route.handler(c)
    } catch (err) {
      if (res.headersSent) return res.end()
      const status = Number(err?.status) || 500
      sendJson(res, status, { error: status >= 500 ? 'internal_error' : 'bad_request', message: status >= 500 ? undefined : String(err?.message ?? '') })
    }
  }

  function personas() {
    return USERS.map(u => ({
      handle: u.handle,
      roleLabel: u.role,
      authKind: 'bearer',
      secret: personaToken(u),
      canaryMarkers: [],
      userId: u.id,
      tenantId: u.tenantId,
    }))
  }

  return { ctx, router, handle, personas }
}
