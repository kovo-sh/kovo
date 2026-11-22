import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { get } from 'node:http'
import type { AddressInfo } from 'node:net'
import type { PersonaId, PersonaCredential, VariantPlan } from '../lib/types.ts'
import { createOracle, type Oracle } from '../lib/oracle.ts'
import { createHttpApp, type HttpApp } from '../lib/http.ts'

function personas(): Record<PersonaId, PersonaCredential> {
  const mk = (id: PersonaId): PersonaCredential => ({ id, email: `${id}@ex.test`, password: 'pw', tenant: 't1', role: 'member' })
  return { persona_a: mk('persona_a'), persona_b: mk('persona_b'), admin: mk('admin'), viewer: mk('viewer') }
}

const plan: VariantPlan = {
  app: 'acme-saas', seed: 1, seedSet: 'dev', apiPrefix: '/api',
  routes: { ping: { method: 'GET', path: '/api/ping' } },
  params: {}, idFormat: 'int', sites: {}, personas: personas(), canarySalt: 'salt',
}

let app: HttpApp
let oracle: Oracle
let base: string
let uiDir: string

// raw GET that preserves a literal, non-normalized request path (so traversal can be exercised)
function rawGet(path: string): Promise<{ status: number; body: string }> {
  const { port } = app.server.address() as AddressInfo
  return new Promise((resolve, reject) => {
    get({ host: '127.0.0.1', port, path }, (res) => {
      let body = ''
      res.on('data', (c) => (body += c))
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body }))
    }).on('error', reject)
  })
}

before(async () => {
  uiDir = mkdtempSync(join(tmpdir(), 'rb-ui-'))
  mkdirSync(join(uiDir, 'assets'), { recursive: true })
  writeFileSync(join(uiDir, 'index.html'), '<!doctype html><title>SPA root</title>')
  writeFileSync(join(uiDir, 'assets', 'app.js'), 'console.log("asset-body")')
  oracle = createOracle({ app: 'acme-saas' })
  app = createHttpApp({ plan, oracle, resolveActor: () => ({ actor: 'anonymous', tenant: null, sessionId: null }) })
  app.static(uiDir)
  await app.listen()
  base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`
})
after(() => { app.close(); rmSync(uiDir, { recursive: true, force: true }) })

test('serves index.html and a nested asset', async () => {
  const idx = await fetch(`${base}/`)
  assert.ok((await idx.text()).includes('SPA root'))
  const js = await fetch(`${base}/assets/app.js`)
  assert.equal(js.status, 200)
  assert.ok((await js.text()).includes('asset-body'))
})

test('SPA fallback for /dashboard marks spaFallback', async () => {
  const r = await fetch(`${base}/dashboard`)
  assert.equal(r.status, 200)
  assert.ok((await r.text()).includes('SPA root'))
  const log = oracle.requests().filter((e) => e.path === '/dashboard').at(-1)!
  assert.equal(log.spaFallback, true)
})

test('path traversal (literal and encoded) is refused, never served', async () => {
  const a = await rawGet('/../../../../etc/passwd')
  assert.ok(a.status === 404 || a.status === 400, `literal traversal status ${a.status}`)
  assert.ok(!a.body.includes('root:'))
  const b = await rawGet('/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd')
  assert.ok(b.status === 404 || b.status === 400, `encoded traversal status ${b.status}`)
  assert.ok(!b.body.includes('root:'))
  const c = await rawGet('/assets/..%2f..%2findex.html/../../../etc/passwd')
  assert.ok(!c.body.includes('root:'))
})
