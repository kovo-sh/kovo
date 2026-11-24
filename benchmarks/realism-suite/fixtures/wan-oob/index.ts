// Realism Fixture #2 — WAN jitter + asynchronous out-of-band callbacks.
// A rotating-nonce edge proxy adds 50–300 ms of seeded latency in front of an app
// whose background worker fires SSRF / XXE / blind-SQLi callbacks 15–30 s after the
// HTTP response (tests shrink the delay). All callbacks land on a loopback collector.
import { Router, jsonBody, sendHtml, sendJson, sendText, serve, type Ctx } from '../../lib/http.ts'
import { assertLocalLabAllowed } from '../../lib/safety.ts'
import { hexToken, intBetween, makeRng, type Rng } from '../../lib/rand.ts'
import type { ApiRefEntry, FixtureStartOptions, Persona, StartedFixture } from '../../lib/types.ts'

export const DEFAULT_JITTER_MS: [number, number] = [50, 300]
export const DEFAULT_CALLBACK_DELAY_MS: [number, number] = [15_000, 30_000]

/** Hard ceiling for the blind-SQLi branch's server-side delay (a probe never stalls a scan). */
export const MAX_SQLI_DELAY_MS = 5000

/**
 * Parse the delay a time-based SQLi payload asks the database to sleep for.
 *
 * The fixture is a *timing* oracle for blind SQL injection: the injected branch must take a real,
 * attacker-chosen amount of time while returning a byte-identical body. Only an explicit
 * sleep/delay expression delays the response — ordinary boolean injections (including false ones)
 * stay fast, so a scanner cannot "confirm" timing from a boolean payload.
 *
 * Supported shapes match the engine's payload families:
 *  - MySQL `SLEEP(seconds)`
 *  - PostgreSQL `pg_sleep(seconds)`
 *  - MSSQL `WAITFOR DELAY 'h:m:s'`
 *  - SQLite `RANDOMBLOB(bytes)` (the engine's busy-loop primitive, ~25 000 bytes per ms)
 */
export function injectedTimeDelayMs(query: string): number | null {
  let q = query
  try { q = decodeURIComponent(q) } catch { /* keep the raw value */ }
  const clamp = (ms: number): number => Math.max(150, Math.min(MAX_SQLI_DELAY_MS, Math.round(ms)))
  const seconds = /(?:^|[^a-z_])SLEEP\s*\(\s*([0-9]+(?:\.[0-9]+)?)\s*\)/i.exec(q)
  if (seconds) return clamp(Number(seconds[1]) * 1000)
  const pg = /pg_sleep\s*\(\s*([0-9]+(?:\.[0-9]+)?)\s*\)/i.exec(q)
  if (pg) return clamp(Number(pg[1]) * 1000)
  const waitfor = /WAITFOR\s+DELAY\s+'\s*(\d+):(\d+):(\d+(?:\.\d+)?)\s*'/i.exec(q)
  if (waitfor) {
    const total = Number(waitfor[1]) * 3600 + Number(waitfor[2]) * 60 + Number(waitfor[3])
    return clamp(total * 1000)
  }
  const blob = /RANDOMBLOB\s*\(\s*(\d+)\s*\)/i.exec(q)
  if (blob) return clamp(Number(blob[1]) / 25_000)
  return null
}

export interface CallbackEvent {
  kind: 'ssrf' | 'xxe' | 'webhook' | 'sqli'
  token: string
  path: string
  at: number
}

export interface WanOobFixture extends StartedFixture {
  backendOrigin: string
  proxyOrigin: string
  collectorOrigin: string
  timing: { jitterMs: [number, number]; callbackDelayMs: [number, number] }
  collector: { events: () => CallbackEvent[]; clear: () => void }
  worker: { pending: () => number; completed: () => number }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export async function start(options: FixtureStartOptions = {}): Promise<WanOobFixture> {
  assertLocalLabAllowed()
  const rng: Rng = makeRng(options.seed ?? 42)
  const jitterRange = options.jitterMs ?? DEFAULT_JITTER_MS
  const callbackRange = options.callbackDelayMs ?? DEFAULT_CALLBACK_DELAY_MS

  // ---------- OOB collector ----------
  const collectorEvents: CallbackEvent[] = []
  const collector = new Router()
  const record = (ctx: Ctx, kind: CallbackEvent['kind']) => {
    const token = ctx.query.get('token') ?? 'none'
    collectorEvents.push({ kind, token, path: ctx.path, at: Date.now() })
    sendText(ctx.res, 200, 'ok')
  }
  collector.get('/ssrf', (ctx) => record(ctx, 'ssrf'))
  collector.get('/xxe', (ctx) => record(ctx, 'xxe'))
  collector.get('/webhook', (ctx) => record(ctx, 'webhook'))
  collector.get('/sqli', (ctx) => record(ctx, 'sqli'))
  collector.get('/__collector__/events', (ctx) => sendJson(ctx.res, 200, { events: collectorEvents }))
  collector.get('/health', (ctx) => sendJson(ctx.res, 200, { ok: true, host: 'collector.local' }))
  const collectorServer = await serve(collector, { name: 'collector.local' })

  // ---------- background worker ----------
  const timers = new Set<ReturnType<typeof setTimeout>>()
  const pending = new Set<string>()
  let completed = 0
  let jobSeq = 0
  const worker = {
    schedule(kind: CallbackEvent['kind'], token: string, work: () => Promise<void>): string {
      const id = `job-${++jobSeq}`
      const delay = intBetween(rng, callbackRange[0], callbackRange[1])
      pending.add(id)
      const timer = setTimeout(() => {
        timers.delete(timer)
        void (async () => {
          try {
            await work()
          } catch {
            // A job failure never surfaces synchronously — the caller already got its 202.
          } finally {
            pending.delete(id)
            completed++
          }
        })()
      }, delay)
      timers.add(timer)
      return id
    },
  }

  const collectorUrl = (path: string, kind: CallbackEvent['kind'], token: string) =>
    `${collectorServer.origin}/${path}?token=${encodeURIComponent(token)}&kind=${kind}`

  async function fireCallback(url: string): Promise<void> {
    const parsed = new URL(url)
    const loopback = parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost'
    if (!loopback) return // fixture-internal egress allowlist
    try {
      await fetch(parsed.toString())
    } catch {
      // collector may already be stopping; nothing to do
    }
  }

  // ---------- app behind the proxy ----------
  const backend = new Router()
  backend.get('/v1/health', (ctx) => sendJson(ctx.res, 200, { ok: true, host: 'backend.local' }))
  backend.get('/v1/catalog/item/:id', (ctx) => sendJson(ctx.res, 200, { id: ctx.params.id, name: 'Parameterized item' }))

  backend.get('/v1/catalog/search', async (ctx) => {
    const q = ctx.query.get('q') ?? ''
    const injected = /('\s*(or|and)\b)|(union\s+select)|(--)/i.test(q)
    if (injected) {
      const token = `sqli-${hexToken(rng, 6)}`
      worker.schedule('sqli', token, () => fireCallback(collectorUrl('sqli', 'sqli', token)))
    }
    // Blind timing oracle: a sleep/delay payload makes this branch genuinely slow, bounded to
    // `MAX_SQLI_DELAY_MS`, while the body stays byte-identical to the benign branch. Boolean-only
    // injections stay fast, so "injection noticed" never masquerades as a timing signal.
    const delayMs = injectedTimeDelayMs(q)
    if (delayMs !== null) await sleep(delayMs)
    sendJson(ctx.res, 200, { results: [], tookMs: 12, cursor: null })
  })

  backend.post('/v1/integrations/webhook-test', (ctx) => {
    const body = jsonBody<{ url?: string; token?: string }>(ctx)
    const jobId = `job-${jobSeq + 1}`
    if (!body?.url) {
      sendJson(ctx.res, 400, { error: 'url_required' })
      return
    }
    const token = body.token ?? `ssrf-${hexToken(rng, 6)}`
    worker.schedule('ssrf', token, () => fireCallback(body.url as string))
    sendJson(ctx.res, 202, { accepted: true, jobId })
  })

  backend.post('/v1/import/preview', (ctx) => {
    const xml = ctx.bodyText
    const system = /<!DOCTYPE[\s\S]*?SYSTEM\s+["']([^"']+)["']/i.exec(xml)
    if (!system) {
      sendJson(ctx.res, 202, { accepted: true, jobId: `job-${jobSeq}` })
      return
    }
    const token = `xxe-${hexToken(rng, 6)}`
    const entityUrl = system[1].includes('token=')
      ? system[1]
      : `${system[1]}${system[1].includes('?') ? '&' : '?'}token=${token}`
    worker.schedule('xxe', token, () => fireCallback(entityUrl))
    sendJson(ctx.res, 202, { accepted: true, jobId: `job-${jobSeq}` })
  })

  backend.post('/v1/import/safe-preview', (ctx) => {
    if (/<!DOCTYPE|<!ENTITY/i.test(ctx.bodyText)) {
      sendJson(ctx.res, 400, { error: 'external_entities_disabled' })
      return
    }
    sendJson(ctx.res, 200, { accepted: true, entities: 0 })
  })

  const WEBHOOK_SECRET = 'rbs_fake_webhook_secret'
  backend.post('/v1/billing/webhook', (ctx) => {
    const provided = ctx.headers['x-webhook-signature']
    // Deliberate realism gap: a missing signature header is treated as a trusted sender.
    if (provided && provided !== `sha256=${WEBHOOK_SECRET}`) {
      sendJson(ctx.res, 401, { error: 'invalid_signature' })
      return
    }
    const body = jsonBody<{ event?: string; amount?: number; token?: string }>(ctx)
    if (body?.token) {
      const token = body.token
      worker.schedule('webhook', token, () => fireCallback(collectorUrl('webhook', 'webhook', token)))
    }
    sendJson(ctx.res, 200, { credited: true, event: body?.event ?? 'invoice.paid', canary: 'rbs_fake_webhook_credit' })
  })

  backend.get('/portal', (ctx) => {
    sendHtml(
      ctx.res,
      200,
      '<!doctype html><html><head><meta name="edge-nonce" content="__NONCE__"></head><body>' +
        '<h1>Partner portal</h1><script nonce="__NONCE__">window.__BOOT__={nonce:"__NONCE__"};</script></body></html>',
    )
  })
  backend.get('/health', (ctx) => sendJson(ctx.res, 200, { ok: true }))
  const backendServer = await serve(backend, { name: 'backend.local' })

  // ---------- edge proxy: latency jitter + rotating nonce ----------
  const proxy = new Router()
  proxy.add('ANY', '*', async (ctx) => {
    const delay = intBetween(rng, jitterRange[0], jitterRange[1])
    await sleep(delay)
    const target = `${backendServer.origin}${ctx.path}${ctx.query.size > 0 ? `?${ctx.query.toString()}` : ''}`
    const headers: Record<string, string> = {}
    for (const [key, value] of Object.entries(ctx.headers)) {
      if (!value) continue
      if (['host', 'content-length', 'connection', 'transfer-encoding'].includes(key)) continue
      headers[key] = value
    }
    const response = await fetch(target, {
      method: ctx.method,
      headers,
      body: ctx.method === 'GET' || ctx.method === 'HEAD' ? undefined : ctx.bodyText,
      redirect: 'manual',
    })
    const contentType = response.headers.get('content-type') ?? 'application/octet-stream'
    let body = await response.text()
    const nonce = hexToken(rng, 8)
    if (contentType.includes('text/html')) body = body.replaceAll('__NONCE__', nonce)
    const extra: Record<string, string> = {
      'x-wan-ms': String(delay),
      'x-edge-nonce': nonce,
      'cache-control': 'no-store',
    }
    if (contentType.includes('text/html')) {
      extra['content-security-policy'] = `default-src 'self'; script-src 'nonce-${nonce}'; object-src 'none'`
    }
    sendText(ctx.res, response.status, body, contentType, extra)
  })
  const proxyServer = await serve(proxy, { name: 'proxy.local' })

  const personas: Persona[] = [
    { id: 'svc-integrations', email: 'integrations@wan.example.invalid', password: 'rb_fake_svc_pw', role: 'service', tenant: 'tenant-wan', notes: 'Integration tester; async jobs return 202.' },
  ]

  const apiRef: ApiRefEntry[] = [
    { origin: 'proxy', method: 'GET', path: '/v1/catalog/search?q=', auth: 'none', notes: 'blind search; identical bodies' },
    { origin: 'proxy', method: 'POST', path: '/v1/integrations/webhook-test', auth: 'none', notes: 'JSON {url}; 202 + async callback' },
    { origin: 'proxy', method: 'POST', path: '/v1/import/preview', auth: 'none', notes: 'XML; async entity resolution' },
    { origin: 'proxy', method: 'POST', path: '/v1/import/safe-preview', auth: 'none', notes: 'hardened importer' },
    { origin: 'proxy', method: 'POST', path: '/v1/billing/webhook', auth: 'none', notes: 'billing event; signature optional' },
    { origin: 'proxy', method: 'GET', path: '/portal', auth: 'none', notes: 'nonce-rotating HTML' },
    { origin: 'collector', method: 'GET', path: '/__collector__/events', auth: 'none', notes: 'observed callbacks' },
  ]

  let stopped = false
  const stop = async () => {
    if (stopped) return
    stopped = true
    for (const timer of timers) clearTimeout(timer)
    timers.clear()
    pending.clear()
    collectorEvents.length = 0
    await Promise.all([proxyServer.close(), backendServer.close(), collectorServer.close()])
  }

  return {
    name: 'wan-oob',
    title: 'WAN latency jitter + async out-of-band callbacks',
    origins: { proxy: proxyServer.origin, backend: backendServer.origin, collector: collectorServer.origin },
    hosts: {
      'edge.local': `127.0.0.1:${proxyServer.port}`,
      'backend.local': `127.0.0.1:${backendServer.port}`,
      'collector.local': `127.0.0.1:${collectorServer.port}`,
    },
    personas,
    api: apiRef,
    backendOrigin: backendServer.origin,
    proxyOrigin: proxyServer.origin,
    collectorOrigin: collectorServer.origin,
    timing: { jitterMs: [...jitterRange], callbackDelayMs: [...callbackRange] },
    collector: { events: () => [...collectorEvents], clear: () => { collectorEvents.length = 0 } },
    worker: { pending: () => pending.size, completed: () => completed },
    stop,
  }
}
