/**
 * Tier-1 regression tests for CLAUDE_AUDIT H-25 and H-26:
 * - H-25: Stream sanitizer preserves legitimate model tool-call arguments (`check_canary`,
 *   `kovo_verify` scripts, auth probes with `token` / `password` / `secret` / `authorization`)
 *   without heuristic corruption while still redacting exact provider API keys and registered
 *   vault secrets (including split-chunk and encoded forms).
 * - H-26: `firstEventTimeoutMs` aborts ONLY when headers / the first chunk fail to arrive in
 *   time and is disarmed once streaming begins, so healthy multi-chunk SSE responses completing
 *   after `firstEventTimeoutMs` never abort mid-stream while stalled/zero-byte responses do.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import { test } from 'node:test'
import { obj, str } from '@earendil-works/pi-schema'
import {
  classifyProviderFailure,
  provider,
} from '../src/server/provider.ts'
import type { UsageEvent } from '../src/server/provider.ts'
import {
  sanitizeProviderStream,
  sanitizeProviderValue,
} from '../src/server/provider-stream.ts'
import type { NamedSecret } from '../src/server/redact.ts'

const providerKey = 'inert-provider-fixture-key-t1-9876'
const vaultSecret = 'vault-persona-secret-value-4242'
const vaultSecrets: NamedSecret[] = [
  { value: vaultSecret, placeholder: '[persona:tenant_a:secret]' },
]

function sse(events: Array<{ type: string } & Record<string, unknown>>, done = false, named = false): string {
  return events.map(event =>
    (named ? `event: ${event.type}\n` : '') + `data: ${JSON.stringify(event)}\n\n`
  ).join('') + (done ? 'data: [DONE]\n\n' : '')
}

function chunks(text: string, size = 19): ReadableStream<Uint8Array> {
  const buf = Buffer.from(text)
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (let offset = 0; offset < buf.length; offset += size) {
        controller.enqueue(buf.subarray(offset, offset + size))
      }
      controller.close()
    },
  })
}

function readEvents(text: string): Array<Record<string, unknown>> {
  return text
    .split('\n')
    .filter(line => line.startsWith('data: ') && line !== 'data: [DONE]')
    .map(line => JSON.parse(line.slice(6)) as Record<string, unknown>)
}

function allowLocalModelForTest(t: { after: (fn: () => void) => void }): void {
  const prev = process.env.KOVO_ALLOW_LOCAL_MODEL
  process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
  t.after(() => {
    if (prev === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
    else process.env.KOVO_ALLOW_LOCAL_MODEL = prev
  })
}

// ============================================================================
// H-25: Model tool-call arguments bypass heuristic credentialField / regex scrubbing
// ============================================================================

test('H-25: Responses function_call arguments preserve token/password/secret/script code while redacting exact vault secrets', async () => {
  const canaryArgs = { token: 'gn_canary_8f3a1b2c9d0e' }
  const verifyScript = [
    "const csrf_token = res.headers['x-csrf-token'];",
    "const password = 'probe-password-123';",
    "const secret = 'probe-secret-value';",
    "const api_key = 'probe-api-key';",
    "const header = 'Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.';",
    "const cookie = 'role=probe';",
    "await ctx.http_send({ path: '/api/login', jsonBody: { password, token: csrf_token } });",
  ].join('\n')
  const authProbeArgs = {
    method: 'POST',
    pathAndQuery: '/api/auth/verify',
    headers: {
      authorization: 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.',
    },
    jsonBody: {
      username: 'probe-user',
      password: 'probe-password',
      token: 'probe-token-value',
      secret: 'probe-secret',
      api_key: 'probe-api-key',
      session_id: 'probe-session-1',
      client_secret: 'probe-client-secret',
      service_role_key: 'probe-role-key',
    },
    leakedVault: `raw=${vaultSecret} b64=${Buffer.from(vaultSecret).toString('base64')}`,
    leakedProviderKey: providerKey,
  }

  const canaryJson = JSON.stringify(canaryArgs)
  const verifyJson = JSON.stringify({ script: verifyScript })
  const authJson = JSON.stringify(authProbeArgs)

  const events = [
    // Call 0: check_canary({ token })
    { type: 'response.output_item.added', output_index: 0, item: { type: 'function_call', call_id: 'c0', name: 'check_canary', arguments: canaryJson.slice(0, 12) } },
    { type: 'response.function_call_arguments.delta', output_index: 0, delta: canaryJson.slice(12) },
    { type: 'response.function_call_arguments.done', output_index: 0, arguments: canaryJson },
    // Call 1: kovo_verify({ script })
    { type: 'response.output_item.added', output_index: 1, item: { type: 'function_call', call_id: 'c1', name: 'kovo_verify', arguments: '' } },
    { type: 'response.function_call_arguments.delta', output_index: 1, delta: verifyJson.slice(0, 64) },
    { type: 'response.function_call_arguments.delta', output_index: 1, delta: verifyJson.slice(64) },
    { type: 'response.function_call_arguments.done', output_index: 1, arguments: verifyJson },
    // Call 2: auth probe with credential-like parameter names AND embedded vault secret + provider key
    { type: 'response.output_item.added', output_index: 2, item: { type: 'function_call', call_id: 'c2', name: 'request_http', arguments: '' } },
    { type: 'response.function_call_arguments.delta', output_index: 2, delta: authJson.slice(0, Math.floor(authJson.length / 2)) },
    { type: 'response.function_call_arguments.delta', output_index: 2, delta: authJson.slice(Math.floor(authJson.length / 2)) },
    { type: 'response.function_call_arguments.done', output_index: 2, arguments: authJson },
    // Non-tool-call prose still runs heuristic redaction
    { type: 'response.output_text.delta', output_index: 3, delta: 'Prose note: password=plain-prose-secret ' + vaultSecret },
    {
      type: 'response.completed',
      response: {
        status: 'completed',
        output: [
          { type: 'function_call', call_id: 'c0', name: 'check_canary', arguments: canaryJson },
          { type: 'function_call', call_id: 'c1', name: 'kovo_verify', arguments: verifyJson },
          { type: 'function_call', call_id: 'c2', name: 'request_http', arguments: authJson },
        ],
      },
    },
  ]

  const safe = await new Response(
    sanitizeProviderStream(chunks(sse(events, true)), providerKey, 'responses', { secrets: vaultSecrets }),
  ).text()
  const out = readEvents(safe)

  // 1. check_canary token passes through unmodified across delta, done, and completed
  const c0Joined = (out[0]!.item as { arguments: string }).arguments + (out[1]!.delta as string)
  assert.deepEqual(JSON.parse(c0Joined), canaryArgs)
  assert.deepEqual(JSON.parse(out[2]!.arguments as string), canaryArgs)

  // 2. kovo_verify script passes through 100% unmodified (no syntax-breaking redaction)
  const c1Joined = (out[4]!.delta as string) + (out[5]!.delta as string)
  assert.deepEqual(JSON.parse(c1Joined), { script: verifyScript })
  assert.deepEqual(JSON.parse(out[6]!.arguments as string), { script: verifyScript })

  // 3. auth probe keys pass through unmodified, while exact vault secret + provider key ARE redacted
  const c2Joined = (out[8]!.delta as string) + (out[9]!.delta as string)
  const parsedC2 = JSON.parse(c2Joined) as typeof authProbeArgs
  assert.deepEqual(parsedC2.headers, authProbeArgs.headers)
  assert.deepEqual(parsedC2.jsonBody, authProbeArgs.jsonBody)
  assert.equal(parsedC2.leakedVault, 'raw=[persona:tenant_a:secret] b64=[persona:tenant_a:secret]')
  assert.equal(parsedC2.leakedProviderKey, '[redacted]')
  assert.deepEqual(JSON.parse(out[10]!.arguments as string), parsedC2)

  // 4. Registered secrets and provider key never appear anywhere in the sanitized stream
  assert.ok(!safe.includes(vaultSecret))
  assert.ok(!safe.includes(Buffer.from(vaultSecret).toString('base64')))
  assert.ok(!safe.includes(providerKey))

  // 5. Non-tool-call prose keeps heuristic credential redaction intact
  assert.ok(!(out[11]!.delta as string).includes('plain-prose-secret'))
  assert.ok((out[11]!.delta as string).includes('[persona:tenant_a:secret]'))

  // 6. Completed output array preserves tool-call arguments identically
  const completedOutput = (out[12]!.response as { output: Array<{ arguments: string }> }).output
  assert.deepEqual(JSON.parse(completedOutput[0]!.arguments), canaryArgs)
  assert.deepEqual(JSON.parse(completedOutput[1]!.arguments), { script: verifyScript })
  assert.deepEqual(JSON.parse(completedOutput[2]!.arguments), parsedC2)
})

test('H-25: Messages tool_use input and input_json_delta preserve tool arguments while redacting exact vault secrets', async () => {
  const toolInput = {
    token: 'gn_canary_msg_001',
    password: 'probe-password',
    secret: 'probe-secret',
    script: "const token = body.csrf_token;\nconst password = 'abc';\n",
    leaked: vaultSecret,
    keyLeak: providerKey,
  }
  const partialJson = JSON.stringify(toolInput)
  const mid = Math.floor(partialJson.length / 2)

  const events = [
    {
      type: 'content_block_start',
      index: 0,
      content_block: {
        type: 'tool_use',
        id: 'toolu_1',
        name: 'kovo_verify',
        input: { token: 'gn_canary_start', password: 'pw', secret: 'sec', leaked: vaultSecret },
      },
    },
    { type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: partialJson.slice(0, mid) } },
    { type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: partialJson.slice(mid) } },
    { type: 'message_stop' },
  ]

  const safe = await new Response(
    sanitizeProviderStream(chunks(sse(events, false, true)), providerKey, 'messages', { secrets: vaultSecrets }),
  ).text()
  const out = readEvents(safe)

  assert.deepEqual((out[0]!.content_block as { input: unknown }).input, {
    token: 'gn_canary_start',
    password: 'pw',
    secret: 'sec',
    leaked: '[persona:tenant_a:secret]',
  })

  const joined = (out[1]!.delta as { partial_json: string }).partial_json +
    (out[2]!.delta as { partial_json: string }).partial_json
  assert.deepEqual(JSON.parse(joined), {
    token: 'gn_canary_msg_001',
    password: 'probe-password',
    secret: 'probe-secret',
    script: "const token = body.csrf_token;\nconst password = 'abc';\n",
    leaked: '[persona:tenant_a:secret]',
    keyLeak: '[redacted]',
  })
  assert.ok(!safe.includes(vaultSecret))
  assert.ok(!safe.includes(providerKey))

  // Outgoing/recorded request payload also preserves function_call / tool_use arguments
  const recordedPayload = sanitizeProviderValue(
    {
      authorization: 'raw-header-value',
      input: [
        { type: 'function_call', name: 'check_canary', arguments: JSON.stringify({ token: 'gn_canary_req', leaked: vaultSecret }) },
      ],
    },
    providerKey,
    undefined,
    vaultSecrets,
  ) as { authorization: string; input: Array<{ arguments: string }> }
  assert.equal(recordedPayload.authorization, '[redacted]', 'non-tool-call credential fields stay redacted')
  assert.deepEqual(JSON.parse(recordedPayload.input[0]!.arguments), {
    token: 'gn_canary_req',
    leaked: '[persona:tenant_a:secret]',
  })
})

test('H-25: End-to-end provider() round-trip delivers unmodified check_canary token and kovo_verify script to pi-ai', async (t) => {
  allowLocalModelForTest(t)
  const canaryToken = 'gn_canary_e2e_deadbeef'
  const verifyScript = "const csrf_token = 'tok_123';\nconst password = 'probe_pw';\nexport default csrf_token + password;"
  const canaryJson = JSON.stringify({ token: canaryToken })
  const verifyJson = JSON.stringify({ script: verifyScript })

  const server = createServer((req, res) => {
    req.resume()
    res.writeHead(200, { 'content-type': 'text/event-stream' })
    res.end(sse([
      { type: 'response.created', response: { id: 'resp_h25', status: 'in_progress' } },
      { type: 'response.output_item.added', output_index: 0, item: { type: 'function_call', id: 'fc_1', call_id: 'call_1', name: 'check_canary', arguments: '' } },
      { type: 'response.function_call_arguments.delta', output_index: 0, delta: canaryJson },
      { type: 'response.function_call_arguments.done', output_index: 0, arguments: canaryJson },
      { type: 'response.output_item.done', output_index: 0, item: { type: 'function_call', id: 'fc_1', call_id: 'call_1', name: 'check_canary', arguments: canaryJson, status: 'completed' } },
      { type: 'response.output_item.added', output_index: 1, item: { type: 'function_call', id: 'fc_2', call_id: 'call_2', name: 'kovo_verify', arguments: '' } },
      { type: 'response.function_call_arguments.delta', output_index: 1, delta: verifyJson },
      { type: 'response.function_call_arguments.done', output_index: 1, arguments: verifyJson },
      { type: 'response.output_item.done', output_index: 1, item: { type: 'function_call', id: 'fc_2', call_id: 'call_2', name: 'kovo_verify', arguments: verifyJson, status: 'completed' } },
      {
        type: 'response.completed',
        response: {
          id: 'resp_h25',
          status: 'completed',
          output: [
            { type: 'function_call', id: 'fc_1', call_id: 'call_1', name: 'check_canary', arguments: canaryJson, status: 'completed' },
            { type: 'function_call', id: 'fc_2', call_id: 'call_2', name: 'kovo_verify', arguments: verifyJson, status: 'completed' },
          ],
          usage: { input_tokens: 100, output_tokens: 50 },
        },
      },
    ], true))
  }).listen(0, '127.0.0.1')
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(resolve => server.close(() => resolve()))
  })
  await once(server, 'listening')
  const addr = server.address()
  assert.ok(addr && typeof addr !== 'string')

  const { models, model } = provider(
    { endpoint: `http://127.0.0.1:${addr.port}/v1`, model: 'mock-h25', protocol: 'responses', key: providerKey },
    'worker-investigation',
    { secrets: vaultSecrets },
  )
  const stream = models.stream(model, {
    systemPrompt: 'Run verification tools.',
    messages: [{ role: 'user', content: 'Check canary and verify.', timestamp: Date.now() }],
    tools: [
      { name: 'check_canary', description: 'Check canary', parameters: obj({ token: str() }) },
      { name: 'kovo_verify', description: 'Run verification script', parameters: obj({ script: str() }) },
    ],
  })
  for await (const _ev of stream) { /* consume */ }
  const result = await stream.result()
  const toolCalls = result.content.filter(part => part.type === 'toolCall')
  assert.equal(toolCalls.length, 2)
  assert.deepEqual(toolCalls[0]!.arguments, { token: canaryToken })
  assert.deepEqual(toolCalls[1]!.arguments, { script: verifyScript })
})

// ============================================================================
// H-26: firstEventTimeoutMs disarmed after first chunk/event; aborts zero-byte stalls
// ============================================================================

test('H-26: SSE stream sending chunk 1 immediately and chunk 2 AFTER firstEventTimeoutMs completes cleanly', async (t) => {
  allowLocalModelForTest(t)
  const server = createServer((req, res) => {
    req.resume()
    res.writeHead(200, { 'content-type': 'text/event-stream' })
    res.write(sse([
      { type: 'response.created', response: { id: 'resp_slow', status: 'in_progress' } },
      { type: 'response.output_item.added', output_index: 0, item: { id: 'msg_1', type: 'message', role: 'assistant', status: 'in_progress', content: [] } },
      { type: 'response.output_text.delta', output_index: 0, content_index: 0, delta: 'chunk-one ' },
    ]))
    // Deliberately pause longer than firstEventTimeoutMs (120 ms), but under idleTimeoutMs (800 ms).
    const timer = setTimeout(() => {
      res.write(sse([
        { type: 'response.output_text.delta', output_index: 0, content_index: 0, delta: 'chunk-two' },
        {
          type: 'response.output_item.done',
          output_index: 0,
          item: {
            id: 'msg_1',
            type: 'message',
            role: 'assistant',
            status: 'completed',
            content: [{ type: 'output_text', text: 'chunk-one chunk-two', annotations: [] }],
          },
        },
        {
          type: 'response.completed',
          response: {
            id: 'resp_slow',
            status: 'completed',
            output: [{
              id: 'msg_1',
              type: 'message',
              role: 'assistant',
              status: 'completed',
              content: [{ type: 'output_text', text: 'chunk-one chunk-two', annotations: [] }],
            }],
            usage: { input_tokens: 250, output_tokens: 40 },
          },
        },
      ], true))
      res.end()
    }, 260)
    timer.unref?.()
  }).listen(0, '127.0.0.1')
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(resolve => server.close(() => resolve()))
  })
  await once(server, 'listening')
  const addr = server.address()
  assert.ok(addr && typeof addr !== 'string')

  const usages: UsageEvent[] = []
  const { models, model } = provider(
    { endpoint: `http://127.0.0.1:${addr.port}/v1`, model: 'mock-h26', protocol: 'responses', key: providerKey },
    'worker-investigation',
    {
      firstEventTimeoutMs: 120,
      idleTimeoutMs: 800,
      totalTimeoutMs: 5_000,
      onUsage: u => usages.push(u),
    },
  )

  const stream = models.stream(model, {
    systemPrompt: 'Stream slowly.',
    messages: [{ role: 'user', content: 'Go.', timestamp: Date.now() }],
  })
  let deltaText = ''
  for await (const ev of stream) {
    if (ev.type === 'text_delta') deltaText += ev.delta
  }
  const result = await stream.result()
  assert.notEqual(result.stopReason, 'error', `Unexpected stream error: ${result.errorMessage}`)
  assert.notEqual(result.stopReason, 'aborted', `Unexpected stream abort: ${result.errorMessage}`)
  assert.equal(deltaText, 'chunk-one chunk-two')
  assert.equal(usages.length, 1)
  assert.equal(usages[0]!.inputTokens, 250)
  assert.equal(usages[0]!.outputTokens, 40)
})

test('H-26: SSE server sending headers + ZERO bytes past firstEventTimeoutMs aborts cleanly', async (t) => {
  allowLocalModelForTest(t)
  const server = createServer((req, res) => {
    req.resume()
    res.writeHead(200, { 'content-type': 'text/event-stream' })
    res.flushHeaders()
    // Intentionally send zero body bytes forever.
  }).listen(0, '127.0.0.1')
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(resolve => server.close(() => resolve()))
  })
  await once(server, 'listening')
  const addr = server.address()
  assert.ok(addr && typeof addr !== 'string')

  const startedAt = Date.now()
  const { models, model } = provider(
    { endpoint: `http://127.0.0.1:${addr.port}/v1`, model: 'mock-zero-bytes', protocol: 'responses', key: providerKey },
    'worker-investigation',
    {
      firstEventTimeoutMs: 120,
      idleTimeoutMs: 3_000,
      totalTimeoutMs: 6_000,
    },
  )

  const stream = models.stream(model, {
    systemPrompt: 'Wait for first event.',
    messages: [{ role: 'user', content: 'Hi.', timestamp: Date.now() }],
  })
  for await (const _ev of stream) { /* consume */ }
  const result = await stream.result()
  const elapsedMs = Date.now() - startedAt

  assert.equal(result.stopReason, 'error')
  assert.match(result.errorMessage ?? '', /timed out before returning the first event/i)
  assert.ok(elapsedMs < 1_500, `Expected abort near firstEventTimeoutMs (120ms), took ${elapsedMs}ms`)
})

test('H-26: Server hanging before response headers aborts cleanly at firstEventTimeoutMs', async (t) => {
  allowLocalModelForTest(t)
  const server = createServer((req, _res) => {
    req.resume()
    // Intentionally never write headers or close the response.
  }).listen(0, '127.0.0.1')
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(resolve => server.close(() => resolve()))
  })
  await once(server, 'listening')
  const addr = server.address()
  assert.ok(addr && typeof addr !== 'string')

  const startedAt = Date.now()
  const { models, model } = provider(
    { endpoint: `http://127.0.0.1:${addr.port}/v1`, model: 'mock-hang-headers', protocol: 'responses', key: providerKey },
    'worker-investigation',
    {
      firstEventTimeoutMs: 120,
      idleTimeoutMs: 3_000,
      totalTimeoutMs: 6_000,
    },
  )

  const stream = models.stream(model, {
    systemPrompt: 'Wait for headers.',
    messages: [{ role: 'user', content: 'Hi.', timestamp: Date.now() }],
  })
  for await (const _ev of stream) { /* consume */ }
  const result = await stream.result()
  const elapsedMs = Date.now() - startedAt

  assert.equal(result.stopReason, 'error')
  assert.match(result.errorMessage ?? '', /timed out before returning the first event/i)
  assert.ok(elapsedMs < 1_500, `Expected header timeout near firstEventTimeoutMs (120ms), took ${elapsedMs}ms`)
})

test('H-26: Active stream that stalls after chunk 1 is still aborted by idleTimeoutMs, and timeout errors classify as transient failover', async (t) => {
  allowLocalModelForTest(t)
  const server = createServer((req, res) => {
    req.resume()
    res.writeHead(200, { 'content-type': 'text/event-stream' })
    res.write(sse([
      { type: 'response.created', response: { id: 'resp_stall', status: 'in_progress' } },
    ]))
    // Disarms firstEventTimeoutMs, then stalls silently forever -> idleTimeoutMs must fire.
  }).listen(0, '127.0.0.1')
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(resolve => server.close(() => resolve()))
  })
  await once(server, 'listening')
  const addr = server.address()
  assert.ok(addr && typeof addr !== 'string')

  const startedAt = Date.now()
  const { models, model } = provider(
    { endpoint: `http://127.0.0.1:${addr.port}/v1`, model: 'mock-idle-stall', protocol: 'responses', key: providerKey },
    'worker-investigation',
    {
      firstEventTimeoutMs: 80,
      idleTimeoutMs: 180,
      totalTimeoutMs: 6_000,
    },
  )

  const stream = models.stream(model, {
    systemPrompt: 'Stall mid-stream.',
    messages: [{ role: 'user', content: 'Hi.', timestamp: Date.now() }],
  })
  for await (const _ev of stream) { /* consume */ }
  const result = await stream.result()
  const elapsedMs = Date.now() - startedAt

  assert.equal(result.stopReason, 'error')
  assert.match(result.errorMessage ?? '', /timed out while waiting for data/i)
  assert.ok(elapsedMs >= 150 && elapsedMs < 1_500, `Expected idle abort near 180ms, took ${elapsedMs}ms`)

  const firstEventTimeout = classifyProviderFailure('The model provider timed out before returning the first event.')
  assert.equal(firstEventTimeout?.kind, 'stall')
  assert.equal(firstEventTimeout?.hard, false)
  assert.equal(firstEventTimeout?.retryable, true)

  const abortTimeout = classifyProviderFailure('The operation was aborted due to timeout')
  assert.equal(abortTimeout?.kind, 'stall')
  assert.equal(abortTimeout?.hard, false)
  assert.equal(abortTimeout?.retryable, true)

  assert.equal(classifyProviderFailure('The operation was aborted by user'), null)
})
