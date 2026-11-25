/**
 * v5 M3 signal contracts: data-anchored parameter inference, noise-tolerant boolean differentials,
 * filter-aware traversal, and browser eligibility for rendered pages. Each vulnerable fixture must
 * signal and each hardened/ignoring fixture must stay silent with a bounded request count.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { test } from 'node:test'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { probeDifferential } from '../src/server/surface-engine.ts'
import {
  formHypotheses,
  inferredBodyParams,
  inferredQueryParams,
  profileCaps,
} from '../scripts/benchmark-probes.ts'
import type { DiscoveredEndpoint } from '../scripts/benchmark-probes.ts'

async function withLocalLab<T>(fn: () => Promise<T>): Promise<T> {
  const prev = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  try { return await fn() } finally {
    if (prev === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prev
  }
}

async function fixture(handler: (req: IncomingMessage, res: ServerResponse) => void) {
  const requests: Array<{ method: string; url: string }> = []
  const server = createServer((req, res) => {
    requests.push({ method: req.method ?? 'GET', url: req.url ?? '/' })
    handler(req, res)
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

const grant = (origin: string): Grant => ({
  origin, tier: 3, allowLocalLab: true, maxRpsPerOrigin: 200,
  canRead: o => o === origin,
  isIdempotentPostAllowed: () => true,
  isStateChangeApproved: () => true,
  audit: () => undefined,
})

function json(res: ServerResponse, status: number, value: unknown): void {
  res.statusCode = status
  res.setHeader('Content-Type', 'application/json')
  res.end(JSON.stringify(value))
}

const caps = profileCaps('v4-full')

function ep(over: Partial<DiscoveredEndpoint> & Pick<DiscoveredEndpoint, 'method' | 'path'>): DiscoveredEndpoint {
  return { params: [], source: 'materialized-surface', ...over }
}

// ---------------------------------------------------------------------------
// Parameter inference
// ---------------------------------------------------------------------------

test('inferred query parameters follow route semantics and are tagged with a purpose', () => {
  const search = inferredQueryParams(ep({ method: 'GET', path: '/api/search/products' }))
  assert.deepEqual(search.map(p => p.name), ['q', 'query', 'term', 'keyword'])
  assert.ok(search.every(p => p.location === 'query' && p.purpose === 'search'))

  const download = inferredQueryParams(ep({ method: 'GET', path: '/api/download/files' }))
  assert.ok(download.length > 0 && download.every(p => p.purpose === 'file'))
  assert.ok(download.some(p => p.name === 'path'))

  // A plain plural collection is not a file-name sink.
  assert.deepEqual(inferredQueryParams(ep({ method: 'GET', path: '/api/assets' })), [])
})

test('inferred body parameters distinguish URL, command, text and template sinks', () => {
  assert.deepEqual(inferredBodyParams(ep({ method: 'PUT', path: '/api/members/1/avatar' })).map(p => p.name)[0], 'avatarUrl')
  assert.equal(inferredBodyParams(ep({ method: 'POST', path: '/api/reports/export' }))[0]?.purpose, 'command')
  assert.equal(inferredBodyParams(ep({ method: 'POST', path: '/api/tickets/1/notes' }))[0]?.purpose, 'text')
  const template = inferredBodyParams(ep({ method: 'POST', path: '/api/docs/render' }))
  assert.ok(template.some(p => p.purpose === 'template' && p.name === 'template'))
})

test('hypothesis formation adds browser eligibility for a parameterless rendered page', () => {
  const endpoints: DiscoveredEndpoint[] = [
    ep({ method: 'GET', path: '/' }),
    ep({ method: 'GET', path: '/wizard' }),
    ep({ method: 'GET', path: '/app-config.json' }),
    ep({ method: 'GET', path: '/api/v1/orders' }),
  ]
  const plan = formHypotheses(endpoints, caps)
  const browser = plan.hypotheses.filter(h => h.probeClass === 'xss_context' && h.browserEligible)
  assert.ok(browser.some(h => h.endpoint.path === '/wizard'), 'interactive page must get a browser hypothesis')
  assert.ok(!browser.some(h => h.endpoint.path === '/app-config.json'), 'static JSON is never a browser target')
  assert.ok(browser.length <= 4, 'browser page fallbacks are bounded')
})

test('hypothesis formation infers a collection filter id as an authorization probe', () => {
  const endpoints: DiscoveredEndpoint[] = [ep({ method: 'GET', path: '/api/files' })]
  const plan = formHypotheses(endpoints, caps)
  const filters = plan.hypotheses.filter(h => h.probeClass === 'authz_matrix' && h.param)
  assert.ok(filters.some(h => h.param?.name === 'projectId' && h.param.location === 'query'))
})

test('stored-XSS hypotheses on text sinks carry downstream read routes', () => {
  const endpoints: DiscoveredEndpoint[] = [
    ep({ method: 'POST', path: '/api/reviews', params: [{ name: 'body', location: 'json', isObjectId: false, isCsrf: false }] }),
    ep({ method: 'GET', path: '/api/reviews' }),
  ]
  const plan = formHypotheses(endpoints, caps)
  const stored = plan.hypotheses.find(h => h.probeClass === 'xss_context' && h.param?.name === 'body')
  assert.equal(stored?.secondOrder, true)
  assert.ok(stored?.readPaths?.includes('/api/reviews'))
})

// ---------------------------------------------------------------------------
// Boolean differential: query echo must not mask the true/false divergence
// ---------------------------------------------------------------------------

const names = ['alpha widget', 'beta widget', 'gamma gadget']

async function likeSearchFixture(injectable: boolean) {
  return fixture((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const q = url.searchParams.get('q') ?? ''
    if (!injectable) return json(res, 200, { fixed: true, items: names.map(n => ({ name: n })) })
    const breakout = /^(.*)%' AND (\d+)=(\d+)-- -$/.exec(q)
    let rows: string[]
    if (breakout) rows = breakout[2] === breakout[3] ? names.filter(n => n.includes(breakout[1])) : []
    else rows = names.filter(n => n.includes(q))
    // The response echoes the query, as real JSON search APIs do.
    return json(res, 200, { query: q, items: rows.map(name => ({ name })) })
  })
}

test('sqli_boolean: LIKE-wrapped search signals despite a query echo', async () => {
  await withLocalLab(async () => {
    const fx = await likeSearchFixture(true)
    try {
      const broker = new RequestBroker({ rejectUnauthorized: false })
      const res = await probeDifferential({
        probeClass: 'sqli_boolean', origin: fx.origin, pathAndQuery: '/search', method: 'GET',
        param: 'q', paramLocation: 'query', baselineValue: 'a',
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.verdict, 'signal')
      const hit = res.anomalies.find(a => a.type === 'boolean_differential')
      assert.ok(hit, JSON.stringify(res.details))
      assert.equal(hit.style, 'like_breakout')
    } finally { await fx.close() }
  })
})

test('sqli_boolean: an ignored parameter stops early without burning the matrix', async () => {
  await withLocalLab(async () => {
    const fx = await likeSearchFixture(false)
    try {
      const broker = new RequestBroker({ rejectUnauthorized: false })
      const res = await probeDifferential({
        probeClass: 'sqli_boolean', origin: fx.origin, pathAndQuery: '/search', method: 'GET',
        param: 'q', paramLocation: 'query', baselineValue: 'a',
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.verdict, 'no_signal')
      assert.ok(res.requestsSent <= 12, `expected an early stop, used ${res.requestsSent} requests`)
    } finally { await fx.close() }
  })
})

// ---------------------------------------------------------------------------
// Traversal: plain payloads only; a single-segment handler must stay quiet
// ---------------------------------------------------------------------------

async function traversalFixture(hardened: boolean) {
  return fixture((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const requested = url.searchParams.get('file') ?? ''
    const serve = (path: string) => {
      if (path === '/etc/passwd') {
        res.statusCode = 200
        res.setHeader('Content-Type', 'text/plain')
        return res.end('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin\n')
      }
      json(res, 404, { error: 'not_found' })
    }
    if (hardened) return serve(`/srv/files/${requested.split('/').filter(Boolean).pop() ?? ''}`)
    const parts = `/${requested}`.split('/')
    const stack: string[] = []
    for (const part of parts) {
      if (!part || part === '.') continue
      if (part === '..') stack.pop()
      else stack.push(part)
    }
    return serve(`/${stack.join('/')}`)
  })
}

test('path_traversal: a real jail escape signals', async () => {
  await withLocalLab(async () => {
    const fx = await traversalFixture(false)
    try {
      const broker = new RequestBroker({ rejectUnauthorized: false })
      const res = await probeDifferential({
        probeClass: 'path_traversal_benign', origin: fx.origin, pathAndQuery: '/download', method: 'GET',
        param: 'file', paramLocation: 'query',
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.verdict, 'signal')
      assert.ok(res.anomalies.some(a => a.type === 'path_traversal_escape'))
    } finally { await fx.close() }
  })
})

test('path_traversal: final-segment hardening stays silent and never double-encodes', async () => {
  await withLocalLab(async () => {
    const fx = await traversalFixture(true)
    try {
      const broker = new RequestBroker({ rejectUnauthorized: false })
      const res = await probeDifferential({
        probeClass: 'path_traversal_benign', origin: fx.origin, pathAndQuery: '/download', method: 'GET',
        param: 'file', paramLocation: 'query',
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.verdict, 'no_signal')
      assert.equal(res.anomalies.length, 0)
      assert.ok(!fx.requests.some(r => /%252f(?:etc|private|app|var)/i.test(r.url)), 'encoded traversal payloads are not sent without filter evidence')
    } finally { await fx.close() }
  })
})
