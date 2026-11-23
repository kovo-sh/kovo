/**
 * v6 XSS occurrence analysis: the reflection analyzer must inspect every canary occurrence, not
 * just the first one. A filter control that HTML-escapes the term must not mask a raw echo later
 * in the same response. Escaped-only echoes and legitimately encoded values stay silent.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { test } from 'node:test'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { analyzeXssReflection } from '../src/server/probes/xss.ts'
import { probeDifferential } from '../src/server/surface-engine.ts'

const CANARY = 'gxssdeadbeef'

function analyze(body: string, mediaType = 'text/html; charset=utf-8') {
  return analyzeXssReflection(body, mediaType, CANARY)
}

// ---------------------------------------------------------------------------
// Multi-occurrence analysis
// ---------------------------------------------------------------------------

test('xss occurrence: first escaped attribute echo does not mask a later raw HTML-body echo', () => {
  // Shape of og.account-search-xss: escaped in the filter input, raw in the results banner.
  const body =
    `<form class="account-filter"><input name="q" value="${CANARY}&quot;&#39;&lt;&gt;" /></form>` +
    `<p class="results-banner">Results for ${CANARY}"'<> (3)</p>` +
    `<ul class="account-results"><li>Example</li></ul>`
  const analysis = analyze(body)
  assert.equal(analysis.reflected, true)
  assert.equal(analysis.occurrences, 2)
  assert.equal(analysis.exploitable, true)
  assert.equal(analysis.context, 'html_body')
  assert.deepEqual(analysis.unencodedChars, ['"', "'", '<', '>'])
})

test('xss occurrence: escaped-only echo stays silent', () => {
  const body =
    `<form class="account-filter"><input name="q" value="${CANARY}&quot;&#39;&lt;&gt;" /></form>` +
    `<p class="results-banner">Results for ${CANARY}&quot;&#39;&lt;&gt; (0)</p>`
  const analysis = analyze(body)
  assert.equal(analysis.reflected, true)
  assert.equal(analysis.exploitable, false)
  assert.deepEqual(analysis.unencodedChars, [])
})

test('xss occurrence: mixed encodings (&lt;, &#x3c;, &quot;) are not raw', () => {
  const body =
    `<div>${CANARY}&lt;&#x3c;&#60;</div>` +
    `<div>${CANARY}&#34;&#x22;&quot;</div>` +
    `<div>${CANARY}&apos;&#39;&#x27;</div>` +
    `<div>${CANARY}&gt;&#x3e;&#62;</div>`
  const analysis = analyze(body)
  assert.equal(analysis.exploitable, false)
  assert.deepEqual(analysis.unencodedChars, [])
})

test('xss occurrence: picks the strongest context among multiple raw echoes', () => {
  const body =
    `<input value="${CANARY}"'<>" />` +
    `<div>${CANARY}"'<></div>`
  const analysis = analyze(body)
  assert.equal(analysis.occurrences, 2)
  assert.equal(analysis.exploitable, true)
  assert.equal(analysis.context, 'html_body')
})

test('xss occurrence: raw echo inside a quoted JS event-handler attribute signals', () => {
  const body = `<button type="button" onclick="go('${CANARY}"'<>')">Run</button>`
  const analysis = analyze(body)
  assert.equal(analysis.exploitable, true)
  assert.equal(analysis.context, 'event_handler_attr')
  assert.ok(analysis.unencodedChars.includes("'"))
})

test('xss occurrence: raw echo inside a single-quoted attribute signals', () => {
  const body = `<input title='${CANARY}"'<>' />`
  const analysis = analyze(body)
  assert.equal(analysis.exploitable, true)
  assert.equal(analysis.context, 'html_attr')
  assert.ok(analysis.unencodedChars.includes("'"))
})

test('xss occurrence: URL-encoded echo in a URL parameter is not a signal', () => {
  const body = `<a href="/search?q=${CANARY}%22%27%3C%3E">search</a>`
  const analysis = analyze(body)
  assert.equal(analysis.reflected, true)
  assert.equal(analysis.exploitable, false)
  assert.deepEqual(analysis.unencodedChars, [])
})

test('xss occurrence: JSON/JS escaped echo in a script string is not a signal', () => {
  const body = `<script>const q = ${JSON.stringify(CANARY + `"'<>`)};</script>`
  const analysis = analyze(body)
  // JSON.stringify escapes the double quote but leaves ' < > literal; < enables a script breakout.
  assert.equal(analysis.context, 'js_string')
  assert.equal(analysis.exploitable, true)
  assert.deepEqual(analysis.unencodedChars, ["'", '<', '>'])
})

test('xss occurrence: fully escaped script string stays silent', () => {
  const body = `<script>const q = "${CANARY}\\u0022\\u0027\\u003c\\u003e";</script>`
  const analysis = analyze(body)
  assert.equal(analysis.exploitable, false)
  assert.deepEqual(analysis.unencodedChars, [])
})

test('xss occurrence: marker echoed without its suffix (sanitizer strip) is not a signal', () => {
  const body = `<input value="${CANARY}" />`
  const analysis = analyze(body)
  assert.equal(analysis.exploitable, false)
})

test('xss occurrence: naive canary string match does not count markup accidentally near the echo', () => {
  const body = `<p>Hello ${CANARY} <strong>world</strong></p>`
  const analysis = analyze(body)
  assert.equal(analysis.exploitable, false)
})

test('xss occurrence: reflection inside an HTML comment is inert', () => {
  const body = `<!-- debug echo: ${CANARY}"'<> -->`
  const analysis = analyze(body)
  assert.equal(analysis.exploitable, false)
})

test('xss occurrence: absent marker reports not reflected', () => {
  const analysis = analyze('<div>nothing here</div>')
  assert.equal(analysis.reflected, false)
  assert.equal(analysis.exploitable, false)
  assert.equal(analysis.occurrences, 0)
})

// ---------------------------------------------------------------------------
// End-to-end probe verdict on the opsportal shape
// ---------------------------------------------------------------------------

async function fixture(handler: (req: IncomingMessage, res: ServerResponse) => void) {
  const server = createServer((req, res) => handler(req, res)).listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('fixture has no port')
  return {
    origin: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) }),
  }
}

const grant = (origin: string): Grant => ({
  origin, tier: 3, allowLocalLab: true, maxRpsPerOrigin: 200,
  canRead: o => o === origin,
  isIdempotentPostAllowed: () => true,
  isStateChangeApproved: () => true,
  audit: () => undefined,
})

function lab(run: () => Promise<unknown>): Promise<unknown> {
  const previous = process.env.GUARDIAN_ALLOW_LOCAL_LAB
  process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'
  return run().finally(() => {
    if (previous === undefined) delete process.env.GUARDIAN_ALLOW_LOCAL_LAB
    else process.env.GUARDIAN_ALLOW_LOCAL_LAB = previous
  })
}

async function probeSearch(escapedBanner: boolean) {
  const escape = (term: string) => term.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] ?? c))
  const render = (term: string) => {
    const banner = escapedBanner ? escape(term) : term
    return `<form><input name="q" value="${escape(term)}" /></form><p class="banner">Results for ${banner}</p>`
  }
  const fx = await fixture((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    res.setHeader('Content-Type', 'text/html; charset=utf-8')
    res.end(render(url.searchParams.get('q') ?? ''))
  })
  try {
    const result = await lab(() => probeDifferential(
      { probeClass: 'xss_context', origin: fx.origin, pathAndQuery: '/search?q=hi', param: 'q' } as unknown as Parameters<typeof probeDifferential>[0],
      new RequestBroker({ rejectUnauthorized: false }),
      grant(fx.origin),
      undefined,
      AbortSignal.timeout(15_000),
    ))
    return result as { verdict: string; anomalies: Array<{ type: string; context?: string }> }
  } finally {
    await fx.close()
  }
}

test('xss occurrence: probe signals when an escaped attribute echo precedes a raw banner echo', async () => {
  const result = await probeSearch(false)
  assert.equal(result.verdict, 'signal')
  const hit = result.anomalies.find(a => a.type === 'xss_context')
  assert.ok(hit)
  assert.equal(hit.context, 'html_body')
})

test('xss occurrence: probe stays silent when every echo is escaped', async () => {
  const result = await probeSearch(true)
  assert.equal(result.verdict, 'no_signal')
  assert.equal(result.anomalies.length, 0)
})
