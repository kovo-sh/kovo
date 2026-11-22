import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createOracle, runWithCtx, noteInput } from '../lib/oracle.ts'
import type { RequestCtx } from '../lib/oracle.ts'
import { createEgress, startInternalService } from '../lib/egress.ts'

function ctx(inputs: string[] = []): RequestCtx {
  return {
    routeKey: 'r.fetch',
    method: 'GET',
    path: '/fetch',
    actor: 'persona_a',
    tenant: 't1',
    sessionId: 's1',
    inputs: inputs.slice(),
    inputSet: new Set(inputs),
    startedAt: Date.now(),
  }
}

test('allowed internal fetch works and emits ssrf only when input-derived', async () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const svc = await startInternalService({
    name: 'metadata',
    internal: true,
    handler: (_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('internal-secret-body')
    },
  })
  try {
    const egress = createEgress({ oracle, internalServices: [svc] })
    const url = `http://127.0.0.1:${svc.port}/latest/meta`

    // not input-derived -> works, no ssrf event
    await runWithCtx(ctx(), async () => {
      const res = await egress.fetch(url)
      assert.equal(res.status, 200)
      assert.equal(res.body, 'internal-secret-body')
    })
    assert.equal(oracle.events().filter((e) => e.kind === 'ssrf_internal_fetch').length, 0)

    // input-derived (url was a user input) -> emits ssrf_internal_fetch
    await runWithCtx(ctx([url]), async () => {
      noteInput(url)
      await egress.fetch(url)
    })
    const ssrf = oracle.events().filter((e) => e.kind === 'ssrf_internal_fetch')
    assert.equal(ssrf.length, 1)
    assert.equal(ssrf[0].sink, 'egress:metadata')

    // localhost normalizes to 127.0.0.1
    await runWithCtx(ctx(), async () => {
      const res = await egress.fetch(`http://localhost:${svc.port}/`)
      assert.equal(res.status, 200)
    })
  } finally {
    await svc.stop()
  }
})

test('blocks every non-loopback host form and unregistered ports', async () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const svc = await startInternalService({ name: 'svc', internal: true, handler: (_q, r) => r.end('ok') })
  try {
    const egress = createEgress({ oracle, internalServices: [svc] })
    const blocked = [
      'http://10.0.0.1/',
      'http://169.254.169.254/latest/meta',
      'http://foo.nip.io/',
      'http://[::1]/',
      'http://2130706433/',
      'http://0x7f000001/',
      'http://017700000001/',
      'http://127.0.0.1@evil.example/',
      'http://127.0.0.1.evil.example/',
      'http://127.0.0.1./',
      `http://127.0.0.1:${svc.port + 1}/`, // unregistered loopback port
    ]
    for (const url of blocked) {
      await assert.rejects(
        () => runWithCtx(ctx(), () => egress.fetch(url)),
        /egress blocked/,
        `expected block: ${url}`,
      )
    }
    const log = oracle.egress()
    assert.equal(log.length, blocked.length)
    assert.ok(log.every((e) => e.allowed === false))
  } finally {
    await svc.stop()
  }
})

test('redirect to a blocked host is refused and logged', async () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const svc = await startInternalService({
    name: 'redir',
    internal: true,
    handler: (_req, res) => {
      res.writeHead(302, { location: 'http://169.254.169.254/latest/meta' })
      res.end()
    },
  })
  try {
    const egress = createEgress({ oracle, internalServices: [svc] })
    await assert.rejects(
      () => runWithCtx(ctx(), () => egress.fetch(`http://127.0.0.1:${svc.port}/go`)),
      /egress blocked/,
    )
    const log = oracle.egress()
    assert.ok(log.some((e) => e.allowed === true)) // first hop allowed
    assert.ok(log.some((e) => e.allowed === false)) // redirect hop blocked
  } finally {
    await svc.stop()
  }
})
