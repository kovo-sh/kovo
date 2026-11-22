import { test } from 'node:test'
import assert from 'node:assert/strict'
import { sign, verify, base64urlEncode } from '../lib/jwt.ts'
import { createOracle } from '../lib/oracle.ts'

test('round-trip HS256 verify ok, no forgery event', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const token = sign({ sub: 'u1' }, 'rb_fake_secret')
  const r = verify(token, { secret: 'rb_fake_secret', algorithms: ['HS256'], oracle })
  assert.equal(r.valid, true)
  assert.deepEqual(r.payload, { sub: 'u1' })
  assert.equal(oracle.events().length, 0)
})

test('alg:none forgery accepted when acceptNone -> token_forgery', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  // hand-crafted token never produced by sign()
  const header = base64urlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }))
  const payload = base64urlEncode(JSON.stringify({ sub: 'admin', role: 'admin' }))
  const forged = `${header}.${payload}.`
  const r = verify(forged, { algorithms: ['none'], acceptNone: true, oracle })
  assert.equal(r.valid, true)
  const ev = oracle.events()
  assert.equal(ev.length, 1)
  assert.equal(ev[0]!.kind, 'token_forgery')
  assert.equal(ev[0]!.detail.alg, 'none')
})

test('alg:none rejected when acceptNone not set (no event)', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const header = base64urlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }))
  const payload = base64urlEncode(JSON.stringify({ sub: 'admin' }))
  const r = verify(`${header}.${payload}.`, { algorithms: ['none'], oracle })
  assert.equal(r.valid, false)
  assert.equal(oracle.events().length, 0)
})

test('tampered HS256 payload rejected, no event', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const token = sign({ sub: 'u1', role: 'member' }, 'rb_fake_secret')
  const parts = token.split('.')
  const tampered = `${parts[0]}.${base64urlEncode(JSON.stringify({ sub: 'u1', role: 'admin' }))}.${parts[2]}`
  const r = verify(tampered, { secret: 'rb_fake_secret', algorithms: ['HS256'], oracle })
  assert.equal(r.valid, false)
  assert.equal(oracle.events().length, 0)
})

test('kid-based keyResolver path verifies', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const keys: Record<string, string> = { k1: 'rb_fake_k1', k2: 'rb_fake_k2' }
  const token = sign({ sub: 'u2' }, keys.k2!, { kid: 'k2' })
  const r = verify(token, {
    keyResolver: (h) => keys[h.kid ?? ''],
    algorithms: ['HS256'],
    oracle,
  })
  assert.equal(r.valid, true)
  assert.equal(r.header?.kid, 'k2')
  assert.equal(oracle.events().length, 0)
})
