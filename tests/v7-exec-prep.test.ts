/**
 * v7 execution-prep — tests for live upstream SSE activity reporting (preventing the 28 s
 * no-token watchdog from killing actively streaming turns) and profile-aware watchdog thresholds.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import { test } from 'node:test'
import {
  DEFAULT_NO_TOKEN_WATCHDOG_MS,
  MEDIUM_THINKING_NO_TOKEN_WATCHDOG_MS,
  REASONING_NO_TOKEN_WATCHDOG_MS,
  resolveProfileNoTokenWatchdogMs,
  sanitizeProviderStream,
} from '../src/server/provider-stream.ts'
import { provider } from '../src/server/provider.ts'

test('sanitizeProviderStream fires onActivity in real time per SSE frame while buffering cross-chunk redaction', async () => {
  const secret = 'sk-secret-split-across-chunks'
  const encoder = new TextEncoder()
  const activityTimes: number[] = []
  let outputChunksBeforeDone = 0
  let sentDone = false

  const upstream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const part1 = secret.slice(0, 14)
      const part2 = secret.slice(14)
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'response.output_text.delta', output_index: 0, delta: `prefix ${part1}` })}\n\n`))
      await new Promise(r => setTimeout(r, 25))
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'response.output_text.delta', output_index: 0, delta: `${part2} suffix` })}\n\n`))
      await new Promise(r => setTimeout(r, 25))
      sentDone = true
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'response.completed', response: { status: 'completed' } })}\n\n`))
      controller.close()
    },
  })

  const sanitized = sanitizeProviderStream(upstream, secret, 'responses', {
    onActivity: () => {
      activityTimes.push(Date.now())
    },
  })
  const reader = sanitized.getReader()
  const decoder = new TextDecoder()
  let output = ''
  for (;;) {
    const next = await reader.read()
    if (next.done) break
    if (!sentDone) outputChunksBeforeDone += 1
    output += decoder.decode(next.value, { stream: true })
  }
  output += decoder.decode()

  // Activity fired on all 3 frames in real time (at least 2 before response.completed).
  assert.equal(activityTimes.length, 3, 'every SSE data frame must signal stream activity')
  assert.ok(activityTimes[2]! - activityTimes[0]! >= 35, 'onActivity must fire incrementally before stream completion')
  // Cross-chunk redaction invariant remains intact: buffered until completion and secret scrubbed.
  assert.equal(outputChunksBeforeDone, 0, 'output stays buffered until completion for cross-chunk redaction')
  assert.ok(!output.includes(secret), 'split secret must still be redacted')
  assert.match(output, /\[redacted\]/)
})

test('provider resets idle timeout and forwards onStreamActivity during slow multi-chunk SSE streams', async () => {
  const server = createServer((req, res) => {
    req.resume()
    res.writeHead(200, { 'content-type': 'text/event-stream' })
    const chunks = [
      `data: ${JSON.stringify({ type: 'response.created', response: { id: 'resp_1', status: 'in_progress' } })}\n\n`,
      `data: ${JSON.stringify({ type: 'response.output_item.added', output_index: 0, item: { id: 'msg_1', type: 'message', role: 'assistant', status: 'in_progress', content: [] } })}\n\n`,
      `data: ${JSON.stringify({ type: 'response.output_text.delta', output_index: 0, content_index: 0, delta: 'hello ' })}\n\n`,
      `data: ${JSON.stringify({ type: 'response.output_text.delta', output_index: 0, content_index: 0, delta: 'world' })}\n\n`,
      `data: ${JSON.stringify({ type: 'response.completed', response: { id: 'resp_1', status: 'completed', output: [{ id: 'msg_1', type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'hello world', annotations: [] }] }] } })}\n\n`,
    ]
    let idx = 0
    const sendNext = () => {
      if (idx >= chunks.length) { res.end(); return }
      res.write(chunks[idx++]!)
      const timer = setTimeout(sendNext, 45)
      timer.unref?.()
    }
    sendNext()
  }).listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address()
  assert.ok(addr && typeof addr !== 'string')
  const endpoint = `http://127.0.0.1:${addr.port}/v1`

  try {
    let activities = 0
    // idleTimeoutMs (120 ms) is shorter than total stream duration (~225 ms), proving upstream
    // SSE frames reset both the provider idle timer and options.onStreamActivity.
    const built = provider(
      { endpoint, model: 'mock-stream', protocol: 'responses', key: 'sk-test-stream-1234' },
      'worker-investigation',
      {
        idleTimeoutMs: 120,
        onStreamActivity: () => { activities += 1 },
      },
    )
    const stream = built.models.stream(
      built.model,
      { systemPrompt: 'test', messages: [{ role: 'user', content: 'hi', timestamp: Date.now() }] },
    )
    for await (const _ev of stream) { /* consume */ }
    assert.ok(activities >= 5, `expected >= 5 upstream SSE activity pings, got ${activities}`)
  } finally {
    await new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) })
  }
})

test('resolveProfileNoTokenWatchdogMs scales cleanly by profile thinking/model and respects env override', () => {
  assert.equal(resolveProfileNoTokenWatchdogMs(undefined, {}), DEFAULT_NO_TOKEN_WATCHDOG_MS)
  assert.equal(resolveProfileNoTokenWatchdogMs({ model: 'gpt-4o-mini', thinkingLevel: 'off', roleAffinity: 'fast' }, {}), DEFAULT_NO_TOKEN_WATCHDOG_MS)
  assert.equal(resolveProfileNoTokenWatchdogMs({ model: 'gpt-4o-mini', thinkingLevel: 'medium', roleAffinity: 'tactical' }, {}), MEDIUM_THINKING_NO_TOKEN_WATCHDOG_MS)
  assert.equal(resolveProfileNoTokenWatchdogMs({ model: 'gpt-4o-mini', thinkingLevel: 'high', roleAffinity: 'tactical' }, {}), REASONING_NO_TOKEN_WATCHDOG_MS)
  assert.equal(resolveProfileNoTokenWatchdogMs({ model: 'deepseek/deepseek-v4.1-flash-1017', thinkingLevel: 'medium', roleAffinity: 'tactical' }, {}), MEDIUM_THINKING_NO_TOKEN_WATCHDOG_MS)
  assert.equal(resolveProfileNoTokenWatchdogMs({ model: 'custom-model', thinkingLevel: 'low', roleAffinity: 'reasoning' }, {}), REASONING_NO_TOKEN_WATCHDOG_MS)
  assert.equal(resolveProfileNoTokenWatchdogMs({ model: 'deepseek/deepseek-v4.1-flash-1017' }, { KOVO_PROVIDER_NO_TOKEN_MS: '90000' }), 90_000)
  assert.equal(resolveProfileNoTokenWatchdogMs(undefined, { KOVO_PROVIDER_NO_TOKEN_MS: '1000' }), 5_000)
  assert.equal(resolveProfileNoTokenWatchdogMs(undefined, { KOVO_PROVIDER_NO_TOKEN_MS: '999999' }), 180_000)
})
