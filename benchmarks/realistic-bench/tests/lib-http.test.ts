import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import type { AddressInfo } from 'node:net'
import type { Actor, PersonaId, PersonaCredential, VariantPlan } from '../lib/types.ts'
import { createOracle, isFromInput, type Oracle } from '../lib/oracle.ts'
import { createHttpApp, type HttpApp, type ResolveActor } from '../lib/http.ts'
import { offOrigin } from '../lib/http-util.ts'
import type { SessionRecord } from '../lib/http-session.ts'

function personas(): Record<PersonaId, PersonaCredential> {
  const mk = (id: PersonaId, role: PersonaCredential['role']): PersonaCredential =>
    ({ id, email: `${id}@ex.test`, password: 'pw', tenant: 't1', role })
  return { persona_a: mk('persona_a', 'owner'), persona_b: mk('persona_b', 'member'), admin: mk('admin', 'admin'), viewer: mk('viewer', 'viewer') }
}

const plan: VariantPlan = {
  app: 'acme-saas', seed: 1, seedSet: 'dev', apiPrefix: '/api',
  routes: {
    echo: { method: 'GET', path: '/api/echo' },
    item: { method: 'GET', path: '/api/items/:id' },
    items: { method: 'POST', path: '/api/items' },
    form: { method: 'POST', path: '/api/form' },
    login: { method: 'POST', path: '/api/login' },
    me: { method: 'GET', path: '/api/me' },
    redir: { method: 'GET', path: '/api/redir' },
    boom: { method: 'GET', path: '/api/boom' },
  },
  params: {}, idFormat: 'int', sites: {}, personas: personas(), canarySalt: 'salt',
}

const resolveActor: ResolveActor = (_req, h) => {
  const sid = h.cookies['rb_sid']
  const rec = h.getSession(sid) as SessionRecord | null
  if (rec) return { actor: (rec.data.actor as Actor) ?? 'persona_a', tenant: 't1', sessionId: sid ?? null }
  return { actor: 'anonymous', tenant: null, sessionId: null }
}

let app: HttpApp
let oracle: Oracle
let base: string

before(async () => {
  oracle = createOracle({ app: 'acme-saas' })
  app = createHttpApp({ plan, oracle, resolveActor })
  app.route('echo', (c) => c.json({ q: c.query.q, fromInput: isFromInput(String(c.query.q)) }))
  app.route('item', (c) => c.json({ id: c.params.id, fromInput: isFromInput(c.params.id) }))
  app.route('items', (c) => c.json({ name: (c.body as { name?: string }).name, fromInput: isFromInput(String((c.body as { name?: string }).name)) }), { encoding: 'json' })
  app.route('form', (c) => c.json({ name: (c.body as Record<string, string>).name, fromInput: isFromInput(String((c.body as Record<string, string>).name)) }), { encoding: 'form' })
  app.route('login', (c) => { c.session.set('actor', 'persona_a'); return c.json({ ok: true }) })
  app.route('me', (c) => c.json({ actor: c.actor }))
  app.route('redir', (c) => c.redirect(c.query.to ? String(c.query.to) : 'https://hardcoded.example/x'))
  app.route('boom', () => { throw new Error('kaboom with secret stack') })
  const port = await app.listen()
  base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port ?? port}`
})
after(() => app.close())

test('route dispatch with :param + noteInput records path param', async () => {
  const r = await fetch(`${base}/api/items/42`)
  assert.deepEqual(await r.json(), { id: '42', fromInput: true })
})

test('json body parsing records input taint', async () => {
  const r = await fetch(`${base}/api/items`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: 'alpha' }) })
  assert.deepEqual(await r.json(), { name: 'alpha', fromInput: true })
})

test('form body parsing records input taint', async () => {
  const r = await fetch(`${base}/api/form`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'name=beta' })
  assert.deepEqual(await r.json(), { name: 'beta', fromInput: true })
})

test('encodingMismatch flagged when content-type family differs from route', async () => {
  await fetch(`${base}/api/items`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'name=x' })
  const log = oracle.requests().filter((e) => e.routeKey === 'items').at(-1)!
  assert.equal(log.encodingMismatch, true)
})

test('256 KiB body limit returns 413', async () => {
  const big = 'a'.repeat(300 * 1024)
  const r = await fetch(`${base}/api/items`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: big }) })
  assert.equal(r.status, 413)
})

test('open_redirect only for input-derived off-origin location', async () => {
  const before = oracle.events().filter((e) => e.kind === 'open_redirect').length
  await fetch(`${base}/api/redir`, { redirect: 'manual' }) // hardcoded off-origin, not from input
  assert.equal(oracle.events().filter((e) => e.kind === 'open_redirect').length, before)
  await fetch(`${base}/api/redir?to=${encodeURIComponent('https://evil.example/pwn')}`, { redirect: 'manual' })
  const evs = oracle.events().filter((e) => e.kind === 'open_redirect')
  assert.equal(evs.length, before + 1)
  assert.equal(evs.at(-1)!.detail.location, 'https://evil.example/pwn')
})

test('offOrigin resolves targets the way a browser does (backslash, protocol-relative, schemes)', () => {
  const host = '127.0.0.1:4321'
  assert.equal(offOrigin('/api/me', host), false)
  assert.equal(offOrigin('/api/me?next=https://x.test', host), false)
  assert.equal(offOrigin('relative/path', host), false)
  assert.equal(offOrigin('', host), false)
  assert.equal(offOrigin('https://evil.example/x', host), true)
  assert.equal(offOrigin('//evil.example/x', host), true)
  assert.equal(offOrigin('https:evil.example/x', host), true)
  assert.equal(offOrigin('/\\evil.example/x', host), true) // browsers fold `\` to `/`
  assert.equal(offOrigin('\\\\evil.example/x', host), true)
})

test('session set/get round-trips; bogus cookie marks sessionLost', async () => {
  const login = await fetch(`${base}/api/login`, { method: 'POST' })
  const setCookie = login.headers.getSetCookie()[0]!
  const sid = setCookie.split(';')[0]!
  const me = await fetch(`${base}/api/me`, { headers: { cookie: sid } })
  assert.deepEqual(await me.json(), { actor: 'persona_a' })

  await fetch(`${base}/api/me`, { headers: { cookie: 'rb_sid=deadbeefdeadbeefdeadbeefdeadbeef' } })
  const log = oracle.requests().filter((e) => e.routeKey === 'me').at(-1)!
  assert.equal(log.sessionLost, true)
})

test('suspicious flag set for input containing <script>', async () => {
  await fetch(`${base}/api/echo?q=${encodeURIComponent('<script>alert(1)</script>')}`)
  const log = oracle.requests().filter((e) => e.routeKey === 'echo').at(-1)!
  assert.equal(log.suspicious, true)
})

test('handler error returns 500 without stack trace', async () => {
  const r = await fetch(`${base}/api/boom`)
  assert.equal(r.status, 500)
  const text = await r.text()
  assert.deepEqual(JSON.parse(text), { error: 'internal' })
  assert.ok(!/kaboom|stack|at /.test(text))
})
