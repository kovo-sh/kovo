// Login bridge self-tests: derive the login route from surface routes, capture cookie or bearer
// credentials, fall back from JSON to form encoding, and refuse non-loopback origins.
import { createServer } from 'node:http'
import test from 'node:test'
import assert from 'node:assert/strict'
import { loginPersonas, pickLoginPath } from '../guardian-login.ts'
import { closeServer, listenLoopback } from '../lib/safety.ts'

const personas = [
  { id: 'persona_a', email: 'a@example.test', password: 'pw-a', role: 'owner' },
  { id: 'persona_b', email: 'b@example.test', password: 'pw-b', role: 'member' },
]

test('pickLoginPath prefers the non-legacy POST login route', () => {
  assert.equal(pickLoginPath([
    { routeKey: 'login', method: 'POST', path: '/api/auth/login' },
    { routeKey: 'legacyLogin', method: 'POST', path: '/api/v1/login' },
  ]), '/api/auth/login')
  assert.equal(pickLoginPath([{ routeKey: 'me', method: 'GET', path: '/api/me' }]), null)
})

test('loginPersonas captures cookies and falls back to form encoding', async () => {
  const server = createServer((req, res) => {
    let body = ''
    req.on('data', chunk => { body += chunk })
    req.on('end', () => {
      if (req.url !== '/api/auth/login' || req.method !== 'POST') { res.writeHead(404).end(); return }
      if (String(req.headers['content-type']).includes('application/json')) {
        res.writeHead(401, { 'content-type': 'application/json' }).end('{"error":"unsupported"}')
        return
      }
      const params = new URLSearchParams(body)
      const email = params.get('email')
      const password = params.get('password')
      const id = personas.find(p => p.email === email && p.password === password)?.id
      if (!id) { res.writeHead(401).end(); return }
      res.writeHead(204, { 'set-cookie': `acme_${id}_sid=${id}-session; Path=/; HttpOnly` }).end()
    })
  })
  const port = await listenLoopback(server)
  const origin = `http://127.0.0.1:${port}`
  try {
    const out = await loginPersonas(origin, '/api/auth/login', personas)
    assert.equal(out.personas.persona_a?.cookie, 'acme_persona_a_sid=persona_a-session')
    assert.equal(out.personas.persona_b?.cookie, 'acme_persona_b_sid=persona_b-session')
    assert.equal(out.personas.persona_a?.role, 'owner')
    assert.equal(out.notes.length, 0)
  } finally {
    await closeServer(server)
  }
})

test('loginPersonas captures bearer tokens from JSON bodies', async () => {
  const server = createServer((req, res) => {
    req.resume()
    req.on('end', () => res.writeHead(200, { 'content-type': 'application/json' }).end('{"access_token":"eyJfake.token.value"}'))
  })
  const port = await listenLoopback(server)
  const origin = `http://127.0.0.1:${port}`
  try {
    const out = await loginPersonas(origin, '/login', [personas[0]!])
    assert.equal(out.personas.persona_a?.token, 'eyJfake.token.value')
    assert.equal(out.personas.persona_a?.cookie, undefined)
  } finally {
    await closeServer(server)
  }
})

test('loginPersonas refuses non-loopback origins without fetching', async () => {
  let called = false
  const fetchImpl = (async () => { called = true; return new Response('') }) as unknown as typeof fetch
  const out = await loginPersonas('https://example.com', '/login', personas, fetchImpl)
  assert.equal(called, false)
  assert.deepEqual(out.personas, {})
  assert.match(out.notes.join(' '), /non-loopback/)
})

test('loginPersonas degrades to notes when no login route exists', async () => {
  const out = await loginPersonas('http://127.0.0.1:1', null, personas)
  assert.deepEqual(out.personas, {})
  assert.match(out.notes.join(' '), /no login route/)
})
