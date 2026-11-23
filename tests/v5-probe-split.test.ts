/**
 * v5.1 probe-split structural contracts.
 *
 * The differential engine's monolithic dispatch is now a static family registry. These tests prove
 * (a) the registry is complete and exclusively owned, (b) every family is reachable by its probe
 * class, and (c) each moved family still emits its documented anomaly on a vulnerable fixture and
 * stays silent on the hardened decoy.
 */
import assert from 'node:assert/strict'
import { createHmac, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { test } from 'node:test'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { probeDifferential } from '../src/server/surface-engine.ts'
import type { DifferentialProbeClass, ProbeDifferentialRequest } from '../src/server/surface-engine.ts'
import { ownedProbeClasses, probeFamilyFor, probeModuleFor, probeModules } from '../src/server/probes/registry.ts'

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// Loopback fixtures are the point of this suite; keep the local-lab gate stable for every test.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

async function fixture(handler: (req: IncomingMessage, res: ServerResponse, body: string) => void | Promise<void>) {
  const requests: Array<{ method: string; url: string; body: string }> = []
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = []
    for await (const chunk of req) chunks.push(chunk as Buffer)
    const body = Buffer.concat(chunks).toString('utf8')
    requests.push({ method: req.method ?? 'GET', url: req.url ?? '/', body })
    await handler(req, res, body)
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

function persona(handle: string, secret: string, origin: string): ResolvedPersona {
  return {
    id: handle, handle, roleLabel: handle, originAllowlist: [origin], authKind: 'bearer',
    headerName: null, secret, canaryMarkers: [],
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

function json(res: ServerResponse, status: number, value: unknown): void {
  res.statusCode = status
  res.setHeader('Content-Type', 'application/json')
  res.end(JSON.stringify(value))
}

async function probe(
  fx: { origin: string },
  req: Omit<ProbeDifferentialRequest, 'origin'> & { origin?: string },
  opts: { personas?: ReadonlyMap<string, ResolvedPersona>; canary?: CanaryBroker } = {},
) {
  return probeDifferential(
    { origin: fx.origin, maxRequests: 40, ...req },
    new RequestBroker({ rejectUnauthorized: false }),
    grant(fx.origin, opts.personas),
    opts.canary,
    AbortSignal.timeout(20_000),
  )
}

const expectedClasses: DifferentialProbeClass[] = [
  'sqli_boolean', 'sqli_time_diff', 'ssti_math', 'ssrf_canary', 'nosqli_type',
  'path_traversal_benign', 'graphql_audit', 'authz_matrix', 'workflow_invariant',
  'xss_context', 'auth_protocol_audit', 'xxe_canary', 'cache_poison_deception', 'mass_assignment',
  'command_injection', 'csrf_state_change', 'webhook_signature_bypass', 'open_redirect_differential',
]

// ---------------------------------------------------------------------------
// Registry structure (no network)
// ---------------------------------------------------------------------------

test('probe registry: every differential class has exactly one static owner', () => {
  const owned = ownedProbeClasses()
  assert.deepEqual([...owned].sort(), [...expectedClasses].sort(), 'registry must cover every DifferentialProbeClass')
  assert.equal(new Set(owned).size, owned.length, 'a class must not be owned twice')
  const dispatched = probeModules.flatMap(m => m.classes)
  assert.equal(dispatched.length, owned.length, 'registry table and ownership map must agree')
  assert.equal(new Set(dispatched).size, dispatched.length, 'no module may declare the same class twice')
})

test('probe registry: each module is reachable by every class it owns', () => {
  assert.equal(probeModules.length, 14)
  for (const mod of probeModules) {
    assert.ok(mod.classes.length > 0, `${mod.family} owns no probe class`)
    for (const cls of mod.classes) {
      assert.equal(probeModuleFor(cls), mod, `${cls} must resolve to ${mod.family}`)
      assert.equal(probeFamilyFor(cls), mod.family)
    }
  }
})

test('probe registry: each module has a unique family name', () => {
  const families = probeModules.map(m => m.family)
  assert.equal(new Set(families).size, families.length)
  for (const required of ['authz', 'injection', 'ssrf', 'xxe', 'workflow', 'jwt', 'cache', 'csrf', 'webhook', 'xss', 'graphql', 'traversal']) {
    assert.ok((families as string[]).includes(required), `missing required family ${required}`)
  }
})

// ---------------------------------------------------------------------------
// Behavioral fixtures: one vulnerable + one decoy per moved family
// ---------------------------------------------------------------------------

test('injection: sqli_boolean signals on a LIKE-wrapped sink and stays silent on a fixed response', async () => {
  {
    const names = ['alpha widget', 'beta widget']
    const make = (injectable: boolean) => fixture((req, res) => {
      const q = new URL(req.url ?? '/', 'http://fixture').searchParams.get('q') ?? ''
      if (!injectable) return json(res, 200, { fixed: true, items: names.map(name => ({ name })) })
      const breakout = /^(.*)%' AND (\d+)=(\d+)-- -$/.exec(q)
      const rows = breakout ? (breakout[2] === breakout[3] ? names.filter(n => n.includes(breakout[1])) : []) : names.filter(n => n.includes(q))
      return json(res, 200, { query: q, items: rows.map(name => ({ name })) })
    })
    const vuln = await make(true)
    try {
      const res = await probe(vuln, { probeClass: 'sqli_boolean', pathAndQuery: '/search', method: 'GET', param: 'q', baselineValue: 'a' })
      assert.equal(res.verdict, 'signal', res.summary)
      assert.ok(res.anomalies.some(a => a.type === 'boolean_differential'))
    } finally { await vuln.close() }
    const decoy = await make(false)
    try {
      const res = await probe(decoy, { probeClass: 'sqli_boolean', pathAndQuery: '/search', method: 'GET', param: 'q', baselineValue: 'a' })
      assert.equal(res.verdict, 'no_signal', res.summary)
      assert.equal(res.anomalies.length, 0)
    } finally { await decoy.close() }
  }
})

test('traversal: a jail escape signals and final-segment hardening stays silent', async () => {
  {
    const make = (hardened: boolean) => fixture((req, res) => {
      const requested = new URL(req.url ?? '/', 'http://fixture').searchParams.get('file') ?? ''
      const last = requested.split('/').filter(Boolean).pop() ?? ''
      if (hardened) {
        // A final-segment handler resolves inside /srv/files; /etc/passwd never exists there.
        void last
        return json(res, 404, { error: 'not_found' })
      }
      const stack: string[] = []
      for (const part of `/${requested}`.split('/')) {
        if (!part || part === '.') continue
        if (part === '..') stack.pop()
        else stack.push(part)
      }
      if (`/${stack.join('/')}` === '/etc/passwd') {
        res.statusCode = 200
        res.setHeader('Content-Type', 'text/plain')
        res.end('root:x:0:0:root:/root:/bin/bash\n')
        return
      }
      return json(res, 200, { file: last })
    })
    const vuln = await make(false)
    try {
      const res = await probe(vuln, { probeClass: 'path_traversal_benign', pathAndQuery: '/download', method: 'GET', param: 'file' })
      assert.equal(res.verdict, 'signal', res.summary)
      assert.ok(res.anomalies.some(a => a.type === 'path_traversal_escape'))
    } finally { await vuln.close() }
    const decoy = await make(true)
    try {
      const res = await probe(decoy, { probeClass: 'path_traversal_benign', pathAndQuery: '/download', method: 'GET', param: 'file' })
      assert.equal(res.verdict, 'no_signal', res.summary)
    } finally { await decoy.close() }
  }
})

test('ssrf: a server-side fetch of the minted canary signals and an ignoring sink stays silent', async () => {
  {
    const canary = new CanaryBroker()
    await canary.startListener({ host: '127.0.0.1', port: 0 })
    try {
      const make = (fetches: boolean) => fixture(async (req, res) => {
        const url = new URL(req.url ?? '/', 'http://fixture').searchParams.get('url') ?? ''
        if (fetches && /^https?:\/\//.test(url)) await fetch(url).catch(() => undefined)
        json(res, 200, { ok: true })
      })
      const vuln = await make(true)
      try {
        const res = await probe(vuln, { probeClass: 'ssrf_canary', pathAndQuery: '/fetch', method: 'GET', ssrfParams: ['url'], waitMs: 1500 }, { canary })
        assert.equal(res.verdict, 'signal', res.summary)
        assert.ok(res.anomalies.some(a => a.type === 'canary_callback'))
      } finally { await vuln.close() }
      const decoy = await make(false)
      try {
        const res = await probe(decoy, { probeClass: 'ssrf_canary', pathAndQuery: '/fetch', method: 'GET', ssrfParams: ['url'], waitMs: 800 }, { canary })
        assert.equal(res.verdict, 'no_signal', res.summary)
      } finally { await decoy.close() }
    } finally { await canary.stopListener() }
  }
})

test('xxe: a DTD canary entity fetched by the parser signals and a static XML sink stays silent', async () => {
  {
    const canary = new CanaryBroker()
    await canary.startListener({ host: '127.0.0.1', port: 0 })
    try {
      const make = (expands: boolean) => fixture(async (_req, res, body) => {
        if (expands) {
          const m = /https?:\/\/[^\s"'>]+guardian-canary-[a-f0-9]+[^\s"'>]*/i.exec(body)
          if (m) await fetch(m[0]).catch(() => undefined)
        }
        res.setHeader('Content-Type', 'application/xml')
        res.end('<ok/>')
      })
      const vuln = await make(true)
      try {
        const res = await probe(vuln, { probeClass: 'xxe_canary', pathAndQuery: '/api/xml', method: 'POST' }, { canary })
        assert.equal(res.verdict, 'signal', res.summary)
        assert.ok(res.anomalies.some(a => a.type === 'xxe_canary_callback'))
      } finally { await vuln.close() }
      const decoy = await make(false)
      try {
        const res = await probe(decoy, { probeClass: 'xxe_canary', pathAndQuery: '/api/xml', method: 'POST' }, { canary })
        assert.equal(res.verdict, 'no_signal', res.summary)
      } finally { await decoy.close() }
    } finally { await canary.stopListener() }
  }
})

test('workflow: a negative quantity that rewrites the total signals and a rejected quantity stays silent', async () => {
  {
    const make = (acceptsNegative: boolean) => fixture((req, res, body) => {
      const parsed = JSON.parse(body || '{}') as Record<string, unknown>
      const qty = Number(parsed.qty ?? 1)
      if (!acceptsNegative && (qty < 1 || qty > 100)) return json(res, 400, { error: 'invalid_quantity' })
      return json(res, 201, { ok: true, subtotal: qty * 1200 })
    })
    const vuln = await make(true)
    try {
      const res = await probe(vuln, { probeClass: 'workflow_invariant', pathAndQuery: '/api/cart/items', method: 'POST', quantityField: 'qty' })
      assert.equal(res.verdict, 'signal', res.summary)
      assert.ok(res.anomalies.some(a => a.type === 'invariant_violation'))
    } finally { await vuln.close() }
    const decoy = await make(false)
    try {
      const res = await probe(decoy, { probeClass: 'workflow_invariant', pathAndQuery: '/api/cart/items', method: 'POST', quantityField: 'qty' })
      assert.equal(res.verdict, 'no_signal', res.summary)
    } finally { await decoy.close() }
  }
})

test('jwt: an alg=none body token signals and a verified-only endpoint stays silent', async () => {
  {
    const email = 'probe@example.test'
    const make = (acceptsNone: boolean) => fixture((req, res, body) => {
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
          if (payload.sub !== email) return json(res, 401, { error: 'invalid_token' })
          if (acceptsNone ? header.alg !== 'none' : header.alg === 'none') return json(res, 401, { error: 'invalid_token' })
          return json(res, 200, { ok: true, access: 'issued' })
        } catch { return json(res, 401, { error: 'invalid_token' }) }
      }
      return json(res, 404, { error: 'not_found' })
    })
    const req = {
      probeClass: 'auth_protocol_audit' as const,
      pathAndQuery: '/api/auth/token', method: 'POST' as const,
      identityClaims: { email, id: 'u-1', role: 'owner', tenant: 'acme' }, tokenFields: ['token'],
    }
    const vuln = await make(true)
    try {
      const res = await probe(vuln, req)
      assert.equal(res.verdict, 'signal', res.summary)
      assert.ok(res.anomalies.some(a => a.type === 'jwt_body_token_bypass'))
    } finally { await vuln.close() }
    const decoy = await make(false)
    try {
      const res = await probe(decoy, req)
      assert.equal(res.verdict, 'no_signal', res.summary)
      assert.equal(res.anomalies.length, 0)
    } finally { await decoy.close() }
  }
})

test('cache: an unkeyed header poisoned entry signals and a host-agnostic cache stays silent', async () => {
  {
    const make = (reflectsHost: boolean) => {
      const poisoned = new Map<string, string>()
      return fixture((req, res) => {
        const u = new URL(req.url ?? '/', 'http://fixture')
        const gcb = u.searchParams.get('_gcb') ?? ''
        const xfh = typeof req.headers['x-forwarded-host'] === 'string' ? req.headers['x-forwarded-host'] : undefined
        if (reflectsHost && xfh && gcb) poisoned.set(gcb, xfh)
        const cached = reflectsHost ? poisoned.get(gcb) : undefined
        if (cached) {
          res.writeHead(200, { 'Content-Type': 'text/html', 'X-Cache': 'HIT', Age: '12' }).end(`host=${cached}`)
          return
        }
        res.writeHead(200, { 'Content-Type': 'text/html', 'X-Cache': 'MISS' }).end('host=clean-origin')
      })
    }
    const vuln = await make(true)
    try {
      const res = await probe(vuln, { probeClass: 'cache_poison_deception', pathAndQuery: '/landing' })
      assert.equal(res.verdict, 'signal', res.summary)
      assert.ok(res.anomalies.some(a => a.type === 'cache_poisoning'))
    } finally { await vuln.close() }
    const decoy = await make(false)
    try {
      const res = await probe(decoy, { probeClass: 'cache_poison_deception', pathAndQuery: '/landing' })
      assert.equal(res.verdict, 'no_signal', res.summary)
    } finally { await decoy.close() }
  }
})

test('csrf: a tokenless cross-origin create signals and a token-enforcing write stays silent', async () => {
  {
    const make = (enforces: boolean) => {
      const rows = new Map<string, { id: string; amount: number }>()
      return fixture((req, res, body) => {
        const url = new URL(req.url ?? '/', 'http://fixture')
        if (req.method === 'POST' && url.pathname === '/api/refunds') {
          const sameOrigin = String(req.headers.origin ?? '') === `http://${req.headers.host}`
          const presented = String(req.headers['x-csrf-token'] ?? '')
          if (enforces && (!sameOrigin || presented !== 'csrf_ok')) return json(res, 403, { error: 'csrf' })
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
    }
    const req = {
      probeClass: 'csrf_state_change' as const,
      pathAndQuery: '/api/refunds', method: 'POST' as const,
      bodyField: 'amount', stateField: 'amount', createReadTemplate: '/api/refunds/:id',
      bodyEncodings: ['form', 'json'] as Array<'json' | 'form'>,
      session: 'bench', foreignOrigin: 'https://untrusted.invalid', maxRequests: 20,
    }
    const vuln = await make(false)
    try {
      const res = await probe(vuln, req)
      assert.equal(res.verdict, 'signal', res.summary)
      assert.ok(res.anomalies.some(a => a.type === 'csrf_state_change'))
    } finally { await vuln.close() }
    const decoy = await make(true)
    try {
      const res = await probe(decoy, req)
      assert.equal(res.verdict, 'no_signal', res.summary)
      assert.equal(res.anomalies.length, 0)
    } finally { await decoy.close() }
  }
})

test('webhook: an inline attacker signing key signals and a server-pinned key stays silent', async () => {
  {
    const serverKey = 'server_pinned_key_123'
    const make = (trustsInlineKey: boolean) => fixture((req, res, body) => {
      if (req.method !== 'POST') return json(res, 404, { error: 'not_found' })
      let parsed: Record<string, unknown>
      try { parsed = JSON.parse(body) as Record<string, unknown> } catch { return json(res, 400, { error: 'bad_json' }) }
      const inline = String(parsed.key ?? '')
      const key = trustsInlineKey && inline ? inline : serverKey
      const sig = String(parsed.signature ?? '')
      const ts = String(parsed.ts ?? '')
      const canonical = `${ts}.${JSON.stringify(parsed.event ?? {})}`
      const expected = createHmac('sha256', key).update(canonical).digest('hex')
      if (!sig || sig !== expected) return json(res, 401, { error: 'bad_signature' })
      return json(res, 200, { ok: true, received: true })
    })
    const req = {
      probeClass: 'webhook_signature_bypass' as const,
      pathAndQuery: '/api/webhooks/receive', method: 'POST' as const,
      webhookBody: { endpoint: 'hook-1', event: { type: 'probe', id: 'evt-1' } },
      webhookHeader: 'x-webhook-signature', maxRequests: 30,
    }
    const vuln = await make(true)
    try {
      const res = await probe(vuln, req)
      assert.equal(res.verdict, 'signal', res.summary)
      assert.ok(res.anomalies.some(a => a.type === 'webhook_signature_bypass'))
    } finally { await vuln.close() }
    const decoy = await make(false)
    try {
      const res = await probe(decoy, req)
      assert.equal(res.verdict, 'no_signal', res.summary)
    } finally { await decoy.close() }
  }
})

test('xss: raw attribute reflection signals and escaped reflection stays silent', async () => {
  {
    const make = (reflects: boolean) => fixture((req, res) => {
      const q = new URL(req.url ?? '/', 'http://fixture').searchParams.get('q') ?? ''
      res.setHeader('Content-Type', 'text/html')
      res.end(reflects ? `<html><body><input value="${q}"></body></html>` : '<html><body><input value="static"></body></html>')
    })
    const vuln = await make(true)
    try {
      const res = await probe(vuln, { probeClass: 'xss_context', pathAndQuery: '/xss?q=1', param: 'q' })
      assert.equal(res.verdict, 'signal', res.summary)
      assert.equal(res.details.context, 'html_attr')
    } finally { await vuln.close() }
    const decoy = await make(false)
    try {
      const res = await probe(decoy, { probeClass: 'xss_context', pathAndQuery: '/xss?q=1', param: 'q' })
      assert.equal(res.verdict, 'no_signal', res.summary)
      assert.equal(res.anomalies.length, 0)
    } finally { await decoy.close() }
  }
})

test('graphql: introspection exposure signals and a locked-down endpoint stays silent', async () => {
  {
    const introspection = {
      data: {
        __schema: {
          queryType: { name: 'Query' },
          mutationType: null,
          types: [
            { name: 'Item', kind: 'OBJECT', fields: [{ name: 'id', type: { kind: 'SCALAR', name: 'ID' } }] },
            { name: 'Query', kind: 'OBJECT', fields: [{ name: 'item', args: [{ name: 'id', type: { kind: 'SCALAR', name: 'ID' } }], type: { kind: 'OBJECT', name: 'Item' } }] },
          ],
        },
      },
    }
    const make = (introspectionEnabled: boolean) => fixture((_req, res, body) => {
      res.setHeader('Content-Type', 'application/json')
      if (body.includes('__schema')) {
        res.end(JSON.stringify(introspectionEnabled ? introspection : { errors: [{ message: 'introspection disabled' }] }))
        return
      }
      if (body.includes('__typename') && !/\w\s*:\s*__typename/.test(body)) {
        res.end(JSON.stringify({ data: { __typename: 'Query' } }))
        return
      }
      if (introspectionEnabled) {
        res.end(JSON.stringify({ data: { item: null } }))
        return
      }
      res.end(JSON.stringify({ errors: [{ message: 'query not allowed' }] }))
    })
    const req = {
      probeClass: 'graphql_audit' as const,
      pathAndQuery: '/graphql', method: 'POST' as const,
      sdl: 'type Item { id: ID! } type Query { item(id: ID!): Item }',
    }
    const vuln = await make(true)
    try {
      const res = await probe(vuln, req)
      assert.equal(res.verdict, 'signal', res.summary)
      assert.ok(res.anomalies.some(a => a.type === 'introspection_enabled'))
    } finally { await vuln.close() }
    const decoy = await make(false)
    try {
      const res = await probe(decoy, req)
      assert.equal(res.verdict, 'no_signal', res.summary)
      assert.equal(res.anomalies.length, 0)
    } finally { await decoy.close() }
  }
})

test('authz: a cross-persona readable object signals and an owner-only object stays silent', async () => {
  {
    const make = (enforcesOwner: boolean) => fixture((req, res) => {
      const url = new URL(req.url ?? '/', 'http://fixture')
      if (url.pathname !== '/api/orders/ord_secret_1') return json(res, 404, { error: 'not_found' })
      const auth = String(req.headers.authorization ?? '')
      if (enforcesOwner && auth !== 'Bearer tok-a') return json(res, 403, { error: 'forbidden' })
      return json(res, 200, { orderId: 'ord_secret_1', owner: 'persona_a', viewer: auth })
    })
    const buildGrantPersonas = (origin: string) => new Map([
      ['persona_a', persona('persona_a', 'tok-a', origin)],
      ['persona_b', persona('persona_b', 'tok-b', origin)],
    ])
    const base = (origin: string) => ({
      probeClass: 'authz_matrix' as const,
      pathAndQuery: '/api/orders/{{id}}',
      resourceIds: ['ord_secret_1'], ownerPersona: 'persona_a', otherPersona: 'persona_b',
      includeAnonymous: true, includeHeaderBypass: true,
    })
    const vuln = await make(false)
    try {
      const res = await probe(vuln, base(vuln.origin), { personas: buildGrantPersonas(vuln.origin) })
      assert.equal(res.verdict, 'signal', res.summary)
      assert.ok(res.anomalies.some(a => a.type === 'unauthorized_access'))
    } finally { await vuln.close() }
    const decoy = await make(true)
    try {
      const res = await probe(decoy, base(decoy.origin), { personas: buildGrantPersonas(decoy.origin) })
      assert.equal(res.verdict, 'no_signal', res.summary)
    } finally { await decoy.close() }
  }
})

test('mass assignment: a persisted privileged field signals and a server-owned field stays silent', async () => {
  {
    const make = (trustsClient: boolean) => {
      let role = 'user'
      return fixture((req, res, body) => {
        if (req.method === 'POST' && req.url === '/api/profile') {
          const parsed = JSON.parse(body || '{}') as Record<string, unknown>
          if (trustsClient && typeof parsed.role === 'string') role = parsed.role
          return json(res, 200, { ok: true, role })
        }
        return json(res, 200, { id: 'u1', role })
      })
    }
    const req = {
      probeClass: 'mass_assignment' as const,
      pathAndQuery: '/api/profile', method: 'POST' as const,
      candidateFields: ['role', 'isAdmin'],
    }
    const vuln = await make(true)
    try {
      const res = await probe(vuln, req)
      assert.equal(res.verdict, 'signal', res.summary)
      assert.ok(res.anomalies.some(a => a.type === 'mass_assignment'))
    } finally { await vuln.close() }
    const decoy = await make(false)
    try {
      const res = await probe(decoy, req)
      assert.equal(res.verdict, 'no_signal', res.summary)
    } finally { await decoy.close() }
  }
})

test('open redirect: an unvalidated off-origin target signals and a pinned redirect stays silent', async () => {
  {
    const make = (validates: boolean) => fixture((req, res) => {
      const target = new URL(req.url ?? '/', 'http://fixture').searchParams.get('next') ?? ''
      if (!/^https?:|^\/\//.test(target) || target.startsWith('/guardian-return-')) {
        res.writeHead(302, { Location: '/home' }).end()
        return
      }
      res.writeHead(302, { Location: validates ? '/home' : target }).end()
    })
    const req = {
      probeClass: 'open_redirect_differential' as const,
      pathAndQuery: '/login', method: 'GET' as const, param: 'next', paramLocation: 'query' as const,
    }
    const vuln = await make(false)
    try {
      const res = await probe(vuln, req)
      assert.equal(res.verdict, 'signal', res.summary)
      assert.ok(res.anomalies.some(a => a.type === 'open_redirect_differential'))
    } finally { await vuln.close() }
    const decoy = await make(true)
    try {
      const res = await probe(decoy, req)
      assert.equal(res.verdict, 'no_signal', res.summary)
    } finally { await decoy.close() }
  }
})
