import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import type { AddressInfo } from 'node:net'
import type { Actor, PersonaId, PersonaCredential, VariantPlan } from '../lib/types.ts'
import { createOracle, type Oracle } from '../lib/oracle.ts'
import { createCanaryRegistry } from '../lib/canary.ts'
import { createHttpApp, type HttpApp, type ResolveActor } from '../lib/http.ts'

function personas(): Record<PersonaId, PersonaCredential> {
  const mk = (id: PersonaId): PersonaCredential => ({ id, email: `${id}@ex.test`, password: 'pw', tenant: 't1', role: 'member' })
  return { persona_a: mk('persona_a'), persona_b: mk('persona_b'), admin: mk('admin'), viewer: mk('viewer') }
}

const plan: VariantPlan = {
  app: 'acme-saas', seed: 1, seedSet: 'dev', apiPrefix: '/api',
  routes: { report: { method: 'GET', path: '/api/report' } },
  params: {}, idFormat: 'int', sites: {}, personas: personas(), canarySalt: 'salt',
}

// actor + tenant chosen by the x-actor header; tenantA owns the canary baked into the response.
const resolveActor: ResolveActor = (_req, h) => {
  const who = h.header('x-actor') ?? 'a'
  const actor: Actor = who === 'b' ? 'persona_b' : 'persona_a'
  return { actor, tenant: who === 'b' ? 'tenantB' : 'tenantA', sessionId: null }
}

let app: HttpApp
let oracle: Oracle
let base: string
let canaryTok: string

before(async () => {
  oracle = createOracle({ app: 'acme-saas' })
  const canaries = createCanaryRegistry('salt')
  canaryTok = canaries.tenantToken('tenantA', 'acct')
  let counter = 0
  app = createHttpApp({ plan, oracle, canaries, resolveActor })
  app.route('report', (c) => c.json({ n: counter++, secret: canaryTok }), { cache: {} })
  await app.listen()
  base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`
})
after(() => app.close())

test('cache hit serves the cached body (handler not re-run)', async () => {
  const r1 = await (await fetch(`${base}/api/report`, { headers: { 'x-actor': 'a' } })).json() as { n: number }
  const r2 = await (await fetch(`${base}/api/report`, { headers: { 'x-actor': 'a' } })).json() as { n: number }
  assert.equal(r1.n, 0)
  assert.equal(r2.n, 0) // served from cache, counter not advanced
})

test('cache_poisoned emitted when a foreign-tenant actor is served a canary-bearing cached entry', async () => {
  const before = oracle.events().filter((e) => e.kind === 'cache_poisoned').length
  const body = await (await fetch(`${base}/api/report`, { headers: { 'x-actor': 'b' } })).json() as { secret: string }
  assert.equal(body.secret, canaryTok) // tenantB actually received tenantA's cached canary
  const evs = oracle.events().filter((e) => e.kind === 'cache_poisoned')
  assert.equal(evs.length, before + 1)
  assert.equal(evs.at(-1)!.detail.token, canaryTok)
})
