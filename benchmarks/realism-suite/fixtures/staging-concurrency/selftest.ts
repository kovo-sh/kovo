// Self-test for Fixture #3 — proves write-BOLA, multi-step checkout trust, the h2c
// double-spend race, run-scoped tagging, and orphan-free cleanup.
import assert from 'node:assert/strict'
import { connect, type ClientHttp2Session } from 'node:http2'
import { RUN_TAG_PREFIX, start } from './index.ts'

interface H2Result {
  status: number
  body: Record<string, unknown>
}

function h2Post(
  session: ClientHttp2Session,
  path: string,
  token: string,
  payload: Record<string, unknown>,
): Promise<H2Result> {
  return new Promise((resolve, reject) => {
    const req = session.request({
      ':method': 'POST',
      ':path': path,
      'content-type': 'application/json',
      authorization: `Bearer ${token}`,
    })
    let status = 0
    let text = ''
    req.setEncoding('utf8')
    req.on('response', (headers) => {
      status = Number(headers[':status'] ?? 0)
    })
    req.on('data', (chunk: string) => {
      text += chunk
    })
    req.on('end', () => {
      try {
        resolve({ status, body: text ? (JSON.parse(text) as Record<string, unknown>) : {} })
      } catch (err) {
        reject(err)
      }
    })
    req.on('error', reject)
    req.end(JSON.stringify(payload))
  })
}

export async function runSelfTest(): Promise<string[]> {
  const checks: string[] = []
  const fixture = await start()
  const app = fixture.origins.app
  const alice = fixture.personas.find((p) => p.id === 'stg-alice')!
  const bob = fixture.personas.find((p) => p.id === 'stg-bob')!
  const runId = 'stg-run-selftest'
  const aliceHeaders = {
    authorization: `Bearer ${alice.token}`,
    'content-type': 'application/json',
    'x-guardian-run-id': runId,
  }
  const bobHeaders = { authorization: `Bearer ${bob.token}`, 'content-type': 'application/json' }

  try {
    assert.equal((await fetch(`${app}/v1/health`)).status, 200)

    // 1. Write-BOLA: an alpha member mutates a beta invoice
    const patch = await fetch(`${app}/v1/invoices/inv-beta-1`, {
      method: 'PATCH',
      headers: aliceHeaders,
      body: JSON.stringify({ total: 1 }),
    })
    assert.equal(patch.status, 200)
    const patched = (await patch.json()) as { invoice: { total: number; tenant: string } }
    assert.equal(patched.invoice.total, 1)
    const bobRead = (await (await fetch(`${app}/v1/invoices/inv-beta-1`, { headers: bobHeaders })).json()) as {
      total: number
    }
    assert.equal(bobRead.total, 1, 'cross-tenant write persisted')
    checks.push('write-bola persists cross-tenant mutation')

    // 2. Report IDOR + scoped invoice decoy
    const report = await fetch(`${app}/v1/reports/rep-beta-1`, { headers: aliceHeaders })
    assert.equal(report.status, 200)
    const reportBody = (await report.json()) as { report: { canary: string } }
    assert.equal(reportBody.report.canary, 'rbs_fake_beta_report_canary')
    assert.equal((await fetch(`${app}/v1/invoices/inv-beta-1`, { headers: aliceHeaders })).status, 403)
    checks.push('report idor + scoped invoice decoy')

    // 3. Checkout: skip quote and override client price
    const start = await fetch(`${app}/v1/checkout/start`, { method: 'POST', headers: aliceHeaders, body: '{}' })
    assert.equal(start.status, 201)
    const cart = (await start.json()) as { cartId: string; unitPrice: number }
    assert.ok(cart.cartId.startsWith(`${RUN_TAG_PREFIX}${runId}-cart-`))
    const quote = await fetch(`${app}/v1/checkout/quote`, {
      method: 'POST',
      headers: aliceHeaders,
      body: JSON.stringify({ cartId: cart.cartId }),
    })
    const quoteBody = (await quote.json()) as { total: number }
    assert.equal(quoteBody.total, 249)
    const pay = await fetch(`${app}/v1/checkout/pay`, {
      method: 'POST',
      headers: aliceHeaders,
      body: JSON.stringify({ cartId: cart.cartId, unitPrice: 1 }),
    })
    const paid = (await pay.json()) as { orderId: string; total: number; quoteSkipped: boolean }
    assert.equal(paid.total, 1)
    assert.equal(paid.quoteSkipped, false)
    assert.ok(paid.orderId.startsWith(`${RUN_TAG_PREFIX}${runId}-order-`))

    const secondCart = (await (
      await fetch(`${app}/v1/checkout/start`, { method: 'POST', headers: aliceHeaders, body: '{}' })
    ).json()) as { cartId: string }
    const skipped = (await (
      await fetch(`${app}/v1/checkout/pay`, {
        method: 'POST',
        headers: aliceHeaders,
        body: JSON.stringify({ cartId: secondCart.cartId }),
      })
    ).json()) as { quoteSkipped: boolean; total: number }
    assert.equal(skipped.quoteSkipped, true, 'payment accepted without a quote')
    checks.push('checkout price tampering + workflow skip')

    // 4. HTTP/2 single-packet double spend
    const session = connect(fixture.h2Origin)
    try {
      const [first, second] = await Promise.all([
        h2Post(session, '/v2/transfers', alice.token ?? '', { fromAccount: 'acct-alpha', amount: 100, idempotencyKey: 'same-key' }),
        h2Post(session, '/v2/transfers', alice.token ?? '', { fromAccount: 'acct-alpha', amount: 100, idempotencyKey: 'same-key' }),
      ])
      assert.deepEqual([first.status, second.status], [200, 200], 'both racing streams succeed')
      assert.equal(first.body.deduplicated, false)
      assert.equal(second.body.deduplicated, false)
      assert.equal(fixture.balance('acct-alpha'), 900, 'two transfers acknowledged but only one debit applied')
      const health = await new Promise<number>((resolve, reject) => {
        const req = session.request({ ':method': 'GET', ':path': '/v2/health' })
        req.on('response', (headers) => {
          resolve(Number(headers[':status'] ?? 0))
          req.resume()
        })
        req.on('error', reject)
        req.end()
      })
      assert.equal(health, 200)
    } finally {
      await new Promise<void>((resolve) => session.close(() => resolve()))
    }
    checks.push('http/2 double-spend race via idempotency bypass')

    // 5. Run-scoped tagging and orphan-free cleanup
    const before = fixture.orphans(runId)
    assert.ok(before.length >= 3, `expected run-tagged entities, got ${before.join(',')}`)
    const cleanup = await fetch(`${app}/__staging__/cleanup?runId=${encodeURIComponent(runId)}`, { method: 'POST' })
    const cleanupBody = (await cleanup.json()) as { remaining: string[]; removed: number }
    assert.equal(cleanup.status, 200)
    assert.deepEqual(cleanupBody.remaining, [])
    assert.ok(cleanupBody.removed >= 3)
    assert.deepEqual(fixture.orphans(runId), [])
    const restored = (await (await fetch(`${app}/v1/invoices/inv-beta-1`, { headers: bobHeaders })).json()) as {
      total: number
    }
    assert.equal(restored.total, 200, 'cleanup restored the mutated seed invoice')
    checks.push('cleanup removes tagged records and restores mutations')

    // 6. stop() performs the same teardown even if cleanup was not called explicitly
    const stopRun = 'stg-run-stop'
    await fetch(`${app}/v1/checkout/start`, {
      method: 'POST',
      headers: { ...aliceHeaders, 'x-guardian-run-id': stopRun },
      body: '{}',
    })
    assert.ok(fixture.orphans(stopRun).length >= 1)
  } finally {
    await fixture.stop()
    assert.deepEqual(fixture.orphans(), [], 'stop leaves zero guardian-qa- records')
    await fixture.stop()
  }
  checks.push('stop leaves zero orphan run-tagged records')
  return checks
}
