/**
 * v5 M3 probes3: anomaly shapes consumed by the merged specs3 synthesizers.
 *
 * These fixtures are deliberately target-agnostic: form-encoded create + detail read, body-token
 * forging, inline webhook keys, and a read-then-write quantity invariant. Each test asserts the exact
 * fields the synthesizer requires, not just that a signal fired.
 */
import assert from 'node:assert/strict'
import { createHmac, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { test } from 'node:test'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { probeDifferential } from '../src/server/surface-engine.ts'
import { formHypotheses, profileCaps } from '../scripts/benchmark-probes.ts'
import type { DiscoveredEndpoint } from '../scripts/benchmark-probes.ts'

async function withLocalLab<T>(fn: () => Promise<T>): Promise<T> {
  const prev = process.env.GUARDIAN_ALLOW_LOCAL_LAB
  process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'
  try { return await fn() } finally {
    if (prev === undefined) delete process.env.GUARDIAN_ALLOW_LOCAL_LAB
    else process.env.GUARDIAN_ALLOW_LOCAL_LAB = prev
  }
}

async function fixture(handler: (req: IncomingMessage, res: ServerResponse, body: string) => void) {
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = []
    for await (const chunk of req) chunks.push(chunk as Buffer)
    handler(req, res, Buffer.concat(chunks).toString('utf8'))
  }).listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('fixture has no port')
  return {
    origin: `http://127.0.0.1:${address.port}`,
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

test('csrf: form-encoded create is proven through the created detail (form encoding + record selector)', async () => {
  await withLocalLab(async () => {
    const rows = new Map<string, { id: string; amount: number }>()
    const fx = await fixture((req, res, body) => {
      const url = new URL(req.url ?? '/', 'http://fixture')
      if (req.method === 'POST' && url.pathname === '/api/refunds') {
        const form = new URLSearchParams(body)
        const amount = Number(form.get('amount') ?? 0)
        const id = randomUUID()
        rows.set(id, { id, amount })
        return json(res, 201, { id, status: 'pending' })
      }
      const detail = /^\/api\/refunds\/([A-Za-z0-9-]+)$/.exec(url.pathname)
      if (req.method === 'GET' && detail) {
        const row = rows.get(detail[1]!)
        return row ? json(res, 200, row) : json(res, 404, { error: 'not_found' })
      }
      return json(res, 404, { error: 'not_found' })
    })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    try {
      const res = await probeDifferential({
        probeClass: 'csrf_state_change',
        origin: fx.origin,
        pathAndQuery: '/api/refunds',
        method: 'POST',
        bodyField: 'amount',
        stateField: 'amount',
        createReadTemplate: '/api/refunds/:id',
        bodyEncodings: ['form', 'json'],
        session: 'bench',
        foreignOrigin: 'https://untrusted.invalid',
        maxRequests: 20,
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.verdict, 'signal', res.summary)
      const hit = res.anomalies.find(a => a.type === 'csrf_state_change')
      assert.ok(hit, 'csrf anomaly required')
      assert.equal(hit.bodyEncoding, 'form')
      assert.equal(hit.create, true)
      assert.equal(hit.stateField, 'amount')
      assert.match(String(hit.readPath), /^\/api\/refunds\/[A-Za-z0-9-]+$/)
      assert.ok(typeof hit.stateRecordId === 'string' && String(hit.readPath).endsWith(String(hit.stateRecordId)))
    } finally {
      await fx.close()
    }
  })
})

test('jwt: an unsigned token in a JSON body is reported with the merged body-token contract', async () => {
  await withLocalLab(async () => {
    const email = 'probe@example.test'
    const fx = await fixture((req, res, body) => {
      const url = new URL(req.url ?? '/', 'http://fixture')
      if (req.method === 'GET' && url.pathname === '/api/me') {
        return json(res, 200, { user: { id: 'u-1', email, role: 'owner', tenant: 'acme' } })
      }
      if (req.method === 'POST' && url.pathname === '/api/auth/token') {
        const token = String((JSON.parse(body || '{}') as Record<string, unknown>).token ?? '')
        const parts = token.split('.')
        if (parts.length !== 3) return json(res, 401, { error: 'invalid_token' })
        try {
          const header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString('utf8')) as { alg?: string }
          const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as { sub?: string }
          if (header.alg !== 'none' || payload.sub !== email) return json(res, 401, { error: 'invalid_token' })
          return json(res, 200, { ok: true, access: 'issued' })
        } catch { return json(res, 401, { error: 'invalid_token' }) }
      }
      return json(res, 404, { error: 'not_found' })
    })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    try {
      const res = await probeDifferential({
        probeClass: 'auth_protocol_audit',
        origin: fx.origin,
        pathAndQuery: '/api/auth/token',
        method: 'POST',
        identityClaims: { email, id: 'u-1', role: 'owner', tenant: 'acme' },
        tokenFields: ['token'],
        maxRequests: 20,
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.verdict, 'signal', res.summary)
      const hit = res.anomalies.find(a => a.type === 'jwt_body_token_bypass')
      assert.ok(hit, 'jwt body anomaly required')
      assert.equal(hit.tokenField, 'token')
      assert.equal(hit.tokenTransport, 'json')
      assert.equal(hit.subject, email)
      assert.equal(hit.method, 'POST')
      assert.equal(hit.path, '/api/auth/token')
      assert.equal(Number(hit.acceptedStatus), 200)
      assert.equal(Number(hit.controlStatus), 401)
    } finally {
      await fx.close()
    }
  })
})

test('webhook: an attacker-supplied inline signing key is reported with a rejected tampered control', async () => {
  await withLocalLab(async () => {
    const fx = await fixture((req, res, body) => {
      if (req.method !== 'POST') return json(res, 404, { error: 'not_found' })
      let parsed: Record<string, unknown>
      try { parsed = JSON.parse(body) as Record<string, unknown> } catch { return json(res, 400, { error: 'bad_json' }) }
      const key = String(parsed.key ?? '')
      const sig = String(parsed.signature ?? '')
      const ts = String(parsed.ts ?? '')
      const canonical = `${ts}.${JSON.stringify(parsed.event ?? {})}`
      const expected = key ? createHmac('sha256', key).update(canonical).digest('hex') : ''
      if (!key || !sig || sig !== expected) return json(res, 401, { error: 'bad_signature' })
      return json(res, 200, { ok: true, received: true })
    })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    try {
      const res = await probeDifferential({
        probeClass: 'webhook_signature_bypass',
        origin: fx.origin,
        pathAndQuery: '/api/webhooks/receive',
        method: 'POST',
        webhookBody: { endpoint: 'hook-1', event: { type: 'probe', id: 'evt-1' } },
        webhookHeader: 'x-webhook-signature',
        maxRequests: 30,
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.verdict, 'signal', res.summary)
      const hit = res.anomalies.find(a => a.type === 'webhook_signature_bypass')
      assert.ok(hit, 'webhook anomaly required')
      assert.match(String(hit.variant), /^inline_key:key\/signature$/)
      assert.equal(hit.proof, 'acceptance')
      assert.equal(hit.controlRejected, true)
      assert.equal(hit.acceptanceAck, true)
      const accepted = hit.body as Record<string, unknown>
      assert.ok(typeof accepted.key === 'string' && String(accepted.key).startsWith('guardian_whk_'))
      assert.ok(typeof accepted.signature === 'string')
      assert.ok(typeof accepted.ts === 'string')
    } finally {
      await fx.close()
    }
  })
})

test('invariant: a negative quantity that changes the conserved total emits the business-logic contract', async () => {
  await withLocalLab(async () => {
    const fx = await fixture((req, res, body) => {
      if (req.method !== 'POST') return json(res, 404, { error: 'not_found' })
      const parsed = JSON.parse(body || '{}') as Record<string, unknown>
      const qty = Number(parsed.qty ?? 1)
      if (qty === 0) return json(res, 400, { error: 'invalid_quantity' })
      return json(res, 201, { ok: true, subtotal: qty * 1200 })
    })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    try {
      const res = await probeDifferential({
        probeClass: 'workflow_invariant',
        origin: fx.origin,
        pathAndQuery: '/api/cart/items',
        method: 'POST',
        quantityField: 'qty',
        maxRequests: 20,
      }, broker, grant(fx.origin), undefined, AbortSignal.timeout(15_000))
      assert.equal(res.verdict, 'signal', res.summary)
      const hit = res.anomalies.find(a => a.type === 'invariant_violation')
      assert.ok(hit, 'invariant anomaly required')
      assert.equal(hit.mode, 'delta')
      assert.equal(hit.field, 'subtotal')
      assert.equal(hit.comparator, 'ne')
      assert.ok(Number(hit.controlValue) > 0)
      assert.ok(Number(hit.expectedValue) < Number(hit.controlValue))
      assert.equal(hit.encoding, 'json')
      assert.equal((hit.controlBody as Record<string, unknown>).qty, 1)
    } finally {
      await fx.close()
    }
  })
})

test('hypothesis shaping: DELETE keeps its verb, cache includes templated public views, and class caps hold', () => {
  const endpoints: DiscoveredEndpoint[] = [
    ep({ method: 'DELETE', path: '/api/admin/members/:memberId', params: [{ name: 'memberId', location: 'path', isObjectId: true, isCsrf: false }] }),
    ep({ method: 'GET', path: '/api/reports/:reportId/public' }),
    ep({ method: 'GET', path: '/api/reports' }),
    ep({ method: 'POST', path: '/api/refunds' }),
    ep({ method: 'GET', path: '/api/refunds/:refundId' }),
    ep({ method: 'GET', path: '/graphql' }),
    ep({ method: 'POST', path: '/graphql' }),
  ]
  const plan = formHypotheses(endpoints, caps)
  const del = plan.hypotheses.find(h => h.endpoint.method === 'DELETE')
  assert.ok(del, 'DELETE authz hypothesis required')
  assert.equal(del.deleteMethod, true)
  assert.equal(del.method, 'POST', 'spec-compatible method stays POST; the probe carries the real verb')

  const cache = plan.hypotheses.filter(h => h.probeClass === 'cache_poison_deception')
  assert.ok(cache.some(h => h.endpoint.path === '/api/reports/:reportId/public'), 'templated public view is cache-eligible')
  assert.ok(cache.length <= 5)

  const csrf = plan.hypotheses.filter(h => h.probeClass === 'csrf_state_change')
  assert.ok(csrf.length <= 6)
  assert.ok(csrf.some(h => h.csrfCreate === true), 'create-shaped form post is collected for CSRF')
  const graphql = plan.hypotheses.filter(h => h.probeClass === 'graphql_audit')
  assert.ok(graphql.length <= 5)
})
