import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { signWebhook, verifyWebhook } from '../lib/webhook.ts'
import { createOracle } from '../lib/oracle.ts'

const SECRET = 'rb_fake_webhook'

test('valid signature verifies with no event', () => {
  const oracle = createOracle({ app: 'shopflow' })
  const ts = Math.floor(Date.now() / 1000)
  const body = '{"order":1}'
  const sig = signWebhook(SECRET, body, ts)
  assert.equal(verifyWebhook(SECRET, body, ts, sig, { oracle }), true)
  assert.equal(oracle.events().length, 0)
})

test('forged signature (computed out-of-band) accepted -> webhook_forgery', () => {
  const oracle = createOracle({ app: 'shopflow' })
  const ts = 1700000000
  const body = '{"order":999,"amount":0}'
  // Attacker computes a valid HMAC directly, bypassing signWebhook() -> never tracked as issued.
  const forged = createHmac('sha256', SECRET).update(`${ts}.${body}`).digest('hex')
  assert.equal(verifyWebhook(SECRET, body, ts, forged, { oracle }), true)
  const ev = oracle.events()
  assert.equal(ev.length, 1)
  assert.equal(ev[0]!.kind, 'webhook_forgery')
})

test('altered body with wrong signature is rejected (no event)', () => {
  const oracle = createOracle({ app: 'shopflow' })
  const ts = 1700000000
  const sig = signWebhook(SECRET, '{"order":1}', ts)
  // body altered, signature left intact -> compare fails
  assert.equal(verifyWebhook(SECRET, '{"order":2}', ts, sig, { oracle }), false)
  assert.equal(oracle.events().length, 0)
})

test('tolerance window rejects stale timestamps', () => {
  const oracle = createOracle({ app: 'shopflow' })
  const ts = 1000 // far in the past
  const body = '{"order":1}'
  const sig = signWebhook(SECRET, body, ts)
  assert.equal(verifyWebhook(SECRET, body, ts, sig, { toleranceSec: 300, nowMs: Date.now(), oracle }), false)
  assert.equal(oracle.events().length, 0)
})

test('verifyWebhook uses a timing-safe comparison', () => {
  const src = readFileSync(fileURLToPath(new URL('../lib/webhook.ts', import.meta.url)), 'utf8')
  assert.match(src, /timingSafeEqual/)
})
