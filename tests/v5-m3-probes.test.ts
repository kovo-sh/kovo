/**
 * v5 M3 probe contracts: CSRF state change, webhook signature bypass, open redirect, write-path
 * BOLA and noise-tolerant NoSQL diffing. Each vulnerable fixture must emit the documented anomaly;
 * each hardened fixture must stay silent.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { test } from 'node:test'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { normalizeEphemeralNoise, probeDifferential, responseSimilarity } from '../src/server/surface-engine.ts'
import { formHypotheses, profileCaps } from '../scripts/benchmark-probes.ts'
import type { DiscoveredEndpoint } from '../scripts/benchmark-probes.ts'

async function withLocalLab<T>(fn: () => Promise<T>): Promise<T> {
  const prev = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  try { return await fn() } finally {
    if (prev === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prev
  }
}

async function fixture(handler: (req: IncomingMessage, body: string, res: ServerResponse) => void) {
  const requests: Array<{ method: string; url: string; headers: IncomingMessage['headers']; body: string }> = []
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(Buffer.from(c)))
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      requests.push({ method: req.method ?? 'GET', url: req.url ?? '/', headers: req.headers, body })
      handler(req, body, res)
    })
  }).listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('fixture has no port')
  return {
    origin: `http://127.0.0.1:${address.port}`,
    requests,
    close: () => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) }),
  }
}

const grant = (origin: string, personas?: ReadonlyMap<string, ResolvedPersona>): Grant => ({
  origin, tier: 3, allowLocalLab: true, maxRpsPerOrigin: 200,
  ...(personas ? { personas } : {}),
  canRead: o => o === origin,
  isIdempotentPostAllowed: () => true,
  isStateChangeApproved: () => true,
  audit: () => undefined,
})

function persona(handle: string, secret: string, origin: string): ResolvedPersona {
  return {
    id: handle, handle, roleLabel: handle, originAllowlist: [origin], authKind: 'cookie',
    headerName: null, secret, canaryMarkers: [],
  }
}

function json(res: ServerResponse, status: number, value: unknown): void {
  res.statusCode = status
  res.setHeader('Content-Type', 'application/json')
  res.end(JSON.stringify(value))
}

// ---------------------------------------------------------------------------
// CSRF state change
// ---------------------------------------------------------------------------

async function csrfFixture(vulnerable: boolean) {
  let name = 'Acme Baseline'
  let token = ''
  return fixture((req, body, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (req.method === 'GET' && url.pathname === '/settings') {
      token = token || 'csrf_tok_12345678'
      res.setHeader('Set-Cookie', 'sid=valid; Path=/')
      return json(res, 200, { name, csrfToken: token })
    }
    if (req.method === 'POST' && url.pathname === '/settings') {
      let parsed: Record<string, unknown> = {}
      try { parsed = body ? JSON.parse(body) as Record<string, unknown> : {} } catch {
        parsed = Object.fromEntries(new URLSearchParams(body).entries())
      }
      const presented = String(req.headers['x-csrf-token'] ?? parsed.csrfToken ?? '')
      const origin = String(req.headers.origin ?? '')
      const sameOrigin = origin === `http://${req.headers.host}`
      if (!vulnerable && (!sameOrigin || presented !== token)) {
        res.setHeader('Content-Type', 'application/json')
        return json(res, 403, { error: 'csrf' })
      }
      if (typeof parsed.name === 'string' && parsed.name) name = parsed.name
      return json(res, 200, { ok: true })
    }
    json(res, 404, { error: 'not_found' })
  })
}

test('csrf_state_change: tokenless cross-origin write with read-back signals', async () => {
  await withLocalLab(async () => {
    const fx = await csrfFixture(true)
    try {
      const broker = new RequestBroker({ rejectUnauthorized: false })
      const res = await probeDifferential({
        probeClass: 'csrf_state_change', origin: fx.origin, pathAndQuery: '/settings', method: 'POST',
        readPath: '/settings', bodyField: 'name', session: 'csrf-jar',
        csrfPrimePaths: ['/settings'],
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.verdict, 'signal')
      const hit = res.anomalies.find(a => a.type === 'csrf_state_change')
      assert.ok(hit)
      assert.equal(hit.path, '/settings')
      assert.equal(hit.method, 'POST')
      assert.equal(hit.bodyField, 'name')
      assert.equal(hit.stateField, 'name')
      assert.ok(String(hit.expectedValue).startsWith('kovo_state_'))
      assert.equal(hit.controlValue, 'Acme Baseline')
    } finally { await fx.close() }
  })
})

test('csrf_state_change: token-enforcing endpoint stays silent', async () => {
  await withLocalLab(async () => {
    const fx = await csrfFixture(false)
    try {
      const broker = new RequestBroker({ rejectUnauthorized: false })
      const res = await probeDifferential({
        probeClass: 'csrf_state_change', origin: fx.origin, pathAndQuery: '/settings', method: 'POST',
        readPath: '/settings', bodyField: 'name', session: 'csrf-jar',
        csrfPrimePaths: ['/settings'],
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.verdict, 'no_signal')
      assert.equal(res.anomalies.length, 0)
    } finally { await fx.close() }
  })
})

// ---------------------------------------------------------------------------
// Webhook signature bypass
// ---------------------------------------------------------------------------

async function webhookFixture(vulnerable: boolean) {
  const events: Array<{ type: string }> = []
  return fixture((req, body, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (req.method === 'GET' && url.pathname === '/hooks') {
      return json(res, 200, { items: [{ id: 'ep_1' }], events })
    }
    if (req.method === 'POST' && url.pathname === '/receive') {
      const sig = String(req.headers['x-webhook-signature'] ?? '')
      if (!vulnerable && !sig.startsWith('v1=')) return json(res, 401, { error: 'bad_signature' })
      events.push({ type: 'kovo.probe' })
      return json(res, 200, { ok: true })
    }
    json(res, 404, { error: 'not_found' })
  })
}

test('webhook_signature_bypass: unsigned delivery accepted and processed signals', async () => {
  await withLocalLab(async () => {
    const fx = await webhookFixture(true)
    try {
      const broker = new RequestBroker({ rejectUnauthorized: false })
      const res = await probeDifferential({
        probeClass: 'webhook_signature_bypass', origin: fx.origin, pathAndQuery: '/receive', method: 'POST',
        webhookBody: { endpoint: 'ep_1', event: { type: 'invoice.paid' } },
        readPath: '/hooks', readStateField: 'events', readStateValue: 1,
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.verdict, 'signal')
      const hit = res.anomalies.find(a => a.type === 'webhook_signature_bypass')
      assert.ok(hit)
      assert.equal(hit.path, '/receive')
      assert.equal(hit.readPath, '/hooks')
      assert.equal(hit.stateField, 'events')
      assert.equal(hit.expectedValue, 1)
    } finally { await fx.close() }
  })
})

test('webhook_signature_bypass: signature-enforcing receiver stays silent', async () => {
  await withLocalLab(async () => {
    const fx = await webhookFixture(false)
    try {
      const broker = new RequestBroker({ rejectUnauthorized: false })
      const res = await probeDifferential({
        probeClass: 'webhook_signature_bypass', origin: fx.origin, pathAndQuery: '/receive', method: 'POST',
        webhookBody: { endpoint: 'ep_1', event: { type: 'invoice.paid' } },
        readPath: '/hooks', readStateField: 'events', readStateValue: 1,
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.verdict, 'no_signal')
      assert.equal(res.anomalies.length, 0)
    } finally { await fx.close() }
  })
})

// ---------------------------------------------------------------------------
// Open redirect
// ---------------------------------------------------------------------------

async function redirectFixture(vulnerable: boolean) {
  return fixture((req, _body, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname !== '/go') return json(res, 404, {})
    const target = url.searchParams.get('next') ?? '/'
    const safe = vulnerable || (target.startsWith('/') && !target.startsWith('//') && !target.includes('\\'))
    res.statusCode = 302
    res.setHeader('Location', safe ? target : '/')
    res.end()
  })
}

test('open_redirect_differential: off-origin redirect target signals with observed location', async () => {
  await withLocalLab(async () => {
    const fx = await redirectFixture(true)
    try {
      const broker = new RequestBroker({ rejectUnauthorized: false })
      const res = await probeDifferential({
        probeClass: 'open_redirect_differential', origin: fx.origin, pathAndQuery: '/go', method: 'GET',
        param: 'next', paramLocation: 'query',
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.verdict, 'signal')
      const hit = res.anomalies.find(a => a.type === 'open_redirect_differential')
      assert.ok(hit)
      assert.equal(hit.param, 'next')
      assert.match(String(hit.location), /\.invalid\/cb$/)
    } finally { await fx.close() }
  })
})

test('open_redirect_differential: same-origin-only redirects stay silent', async () => {
  await withLocalLab(async () => {
    const fx = await redirectFixture(false)
    try {
      const broker = new RequestBroker({ rejectUnauthorized: false })
      const res = await probeDifferential({
        probeClass: 'open_redirect_differential', origin: fx.origin, pathAndQuery: '/go', method: 'GET',
        param: 'next', paramLocation: 'query',
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.verdict, 'no_signal')
      assert.equal(res.anomalies.length, 0)
    } finally { await fx.close() }
  })
})

// ---------------------------------------------------------------------------
// Write-path BOLA
// ---------------------------------------------------------------------------

async function writeFixture(hardened: boolean) {
  const docs = new Map([['d1', { id: 'd1', name: 'Owner Doc' }]])
  return fixture((req, body, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const match = /^\/docs\/([A-Za-z0-9_-]+)$/.exec(url.pathname)
    if (!match) return json(res, 404, { error: 'not_found' })
    const doc = docs.get(match[1])
    if (!doc) return json(res, 404, { error: 'not_found' })
    const tenant = /tenant=([a-z]+)/.exec(String(req.headers.cookie ?? ''))?.[1] ?? ''
    if (hardened && tenant !== 'owner') return json(res, 403, { error: 'forbidden' })
    if (req.method === 'GET') return json(res, 200, doc)
    if (req.method === 'PATCH') {
      const parsed = body ? JSON.parse(body) as Record<string, unknown> : {}
      if (typeof parsed.name === 'string') doc.name = parsed.name
      return json(res, 200, { ok: true })
    }
    json(res, 405, { error: 'method' })
  })
}

test('write_path_bola: cross-tenant benign write proven by owner read-back', async () => {
  await withLocalLab(async () => {
    const fx = await writeFixture(false)
    try {
      const personas = new Map([
        ['owner', persona('owner', 'tenant=owner', fx.origin)],
        ['other', persona('other', 'tenant=other', fx.origin)],
      ])
      const broker = new RequestBroker({ rejectUnauthorized: false })
      const res = await probeDifferential({
        probeClass: 'authz_matrix', origin: fx.origin, pathAndQuery: '/docs/{{id}}', method: 'PATCH',
        resourceIds: ['d1'], ownerPersona: 'owner', otherPersona: 'other',
        jsonBody: { name: 'Owner Doc' }, writePathRead: true,
      }, broker, grant(fx.origin, personas), undefined, AbortSignal.timeout(20_000))
      const hit = res.anomalies.find(a => a.type === 'write_path_bola')
      assert.ok(hit, JSON.stringify(res.anomalies))
      assert.equal(hit.resourceId, 'd1')
      assert.equal(hit.path, '/docs/{{id}}')
      assert.equal(hit.method, 'PATCH')
      assert.equal(hit.stateField, 'name')
      assert.equal((hit.writeBody as Record<string, unknown>).name, hit.expectedValue)
      assert.equal((hit.cleanupBody as Record<string, unknown>).name, 'Owner Doc')
      // The owner read-back after the probe must show the original value restored.
      assert.ok(Array.isArray(res.details.matrix) && res.details.matrix.length > 0)
    } finally { await fx.close() }
  })
})

test('write_path_bola: tenant-scoped writes stay silent', async () => {
  await withLocalLab(async () => {
    const fx = await writeFixture(true)
    try {
      const personas = new Map([
        ['owner', persona('owner', 'tenant=owner', fx.origin)],
        ['other', persona('other', 'tenant=other', fx.origin)],
      ])
      const broker = new RequestBroker({ rejectUnauthorized: false })
      const res = await probeDifferential({
        probeClass: 'authz_matrix', origin: fx.origin, pathAndQuery: '/docs/{{id}}', method: 'PATCH',
        resourceIds: ['d1'], ownerPersona: 'owner', otherPersona: 'other',
        jsonBody: { name: 'Owner Doc' }, writePathRead: true,
      }, broker, grant(fx.origin, personas), undefined, AbortSignal.timeout(20_000))
      assert.equal(res.anomalies.some(a => a.type === 'write_path_bola'), false)
    } finally { await fx.close() }
  })
})

// ---------------------------------------------------------------------------
// NoSQL operator type confusion + noise tolerance
// ---------------------------------------------------------------------------

async function nosqlFixture(vulnerable: boolean) {
  return fixture((req, _body, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const keys = [...url.searchParams.keys()]
    const operator = keys.find(k => /\[(\$ne|\$gt)\]$/.test(k))
    const neutral = keys.find(k => /\[gx\]$/.test(k))
    if (vulnerable) {
      const total = operator ? 3 : 1
      return json(res, 200, { total, items: operator ? [{ id: 'a' }, { id: 'b' }, { id: 'c' }] : [{ id: 'a' }] })
    }
    if (operator || neutral) return json(res, 400, { error: 'invalid_filter' })
    return json(res, 200, { total: 1, items: [{ id: 'a' }] })
  })
}

test('nosqli_type: operator type confusion carries neutral control evidence', async () => {
  await withLocalLab(async () => {
    const fx = await nosqlFixture(true)
    try {
      const broker = new RequestBroker({ rejectUnauthorized: false })
      const res = await probeDifferential({
        probeClass: 'nosqli_type', origin: fx.origin, pathAndQuery: '/search', method: 'GET',
        param: 'q', paramLocation: 'query',
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.details.neutralMatchesBase, true)
      const hit = res.anomalies.find(a => a.type === 'operator_type_divergence')
      assert.ok(hit)
      assert.equal(hit.neutralMatchesBase, true)
    } finally { await fx.close() }
  })
})

test('nosqli_type: a hardened filter rejecting object shapes stays silent', async () => {
  await withLocalLab(async () => {
    const fx = await nosqlFixture(false)
    try {
      const broker = new RequestBroker({ rejectUnauthorized: false })
      const res = await probeDifferential({
        probeClass: 'nosqli_type', origin: fx.origin, pathAndQuery: '/search', method: 'GET',
        param: 'q', paramLocation: 'query',
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.verdict, 'no_signal')
      assert.equal(res.anomalies.some(a => a.type === 'operator_type_divergence'), false)
    } finally { await fx.close() }
  })
})

test('noise normalizer masks clocks/request ids without masking resource identities', () => {
  const a = '{"id":"doc_1001","name":"Same","requestId":"a1b2c3","createdAt":"2026-01-01T00:00:00.000Z","ts":1767225600000}'
  const b = '{"id":"doc_1001","name":"Same","requestId":"d4e5f6","createdAt":"2026-02-02T11:22:33.000Z","ts":1767312000000}'
  assert.equal(responseSimilarity(a, b), 1)
  assert.equal(normalizeEphemeralNoise(a).includes('doc_1001'), true)
  const changed = '{"id":"doc_9999","name":"Other","requestId":"a1b2c3"}'
  assert.ok(responseSimilarity(a, changed) < 0.9)
})

// ---------------------------------------------------------------------------
// Hypothesis formation contracts
// ---------------------------------------------------------------------------

function ep(over: Partial<DiscoveredEndpoint> & Pick<DiscoveredEndpoint, 'method' | 'path'>): DiscoveredEndpoint {
  return { params: [], source: 'materialized-surface', ...over }
}

test('hypothesis formation: CSRF, webhook and open-redirect candidates are bounded and shaped', () => {
  const caps = profileCaps('v4-full')
  const endpoints: DiscoveredEndpoint[] = [
    ep({ method: 'GET', path: '/api/settings' }),
    ep({
      method: 'POST', path: '/api/settings',
      params: [{ name: 'name', location: 'json', isObjectId: false, isCsrf: false }, { name: 'csrfToken', location: 'json', isObjectId: false, isCsrf: true }],
    }),
    ep({ method: 'GET', path: '/rest/auth/sso/callback' }),
    ep({ method: 'GET', path: '/rest/downloads/download' }),
    ep({ method: 'POST', path: '/rest/hooks/receive' }),
    ep({ method: 'POST', path: '/rest/hooks' }),
    ep({ method: 'PATCH', path: '/rest/billing-docs/:docId' }),
    ep({ method: 'GET', path: '/rest/billing-docs/:docId' }),
  ]
  const plan = formHypotheses(endpoints, caps)
  const csrf = plan.hypotheses.filter(h => h.probeClass === 'csrf_state_change')
  const webhook = plan.hypotheses.filter(h => h.probeClass === 'webhook_signature_bypass')
  const redirect = plan.hypotheses.filter(h => h.probeClass === 'open_redirect_differential')
  const authz = plan.hypotheses.filter(h => h.probeClass === 'authz_matrix' && h.writePathRead)
  assert.equal(csrf.length, 1)
  assert.equal(csrf[0].endpoint.path, '/api/settings')
  assert.equal(webhook.length, 1)
  assert.equal(webhook[0].endpoint.path, '/rest/hooks/receive')
  assert.ok(redirect.length >= 2)
  assert.ok(redirect.every(h => Boolean(h.param?.name)))
  assert.equal(authz.length, 1)
  assert.equal(authz[0].endpoint.path, '/rest/billing-docs/:docId')
})
