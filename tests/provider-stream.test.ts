import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { setImmediate as nextTurn } from 'node:timers/promises'
import { agentTurn } from '../src/server/agent-session.ts'
import {
  listModelProfiles,
  privateModelProfiles,
  recordProfileFailure,
  recordProfileSuccess,
  saveModelProfile,
} from '../src/server/model-settings.ts'
import {
  classifyProviderFailure,
  estimateCostUsd,
  extractUsageFromSse,
  isQuotaBody,
  orderProfiles,
  providerPool,
} from '../src/server/provider.ts'
import type { ProviderCall, UsageEvent } from '../src/server/provider.ts'
import {
  defaultStreamResponseLimit,
  sanitizeProviderStream,
} from '../src/server/provider-stream.ts'
import type { NamedSecret } from '../src/server/redact.ts'
import { Store } from '../src/server/store.ts'

const key = 'inert-provider-fixture-secret-z68'
const left = key.slice(0, 16)
const right = key.slice(16)
const personaSecret = 'tenant-a-opaque-session-secret-9921'
const pLeft = personaSecret.slice(0, 17)
const pRight = personaSecret.slice(17)
const personaSecretsList: NamedSecret[] = [
  { value: personaSecret, placeholder: '[persona:tenant_a:secret]' },
]
const marker = '[redacted]'
const prefix = 'Reviewed café '
const suffix = ' for the report.'

function sse(events: Array<{ type: string } & Record<string, unknown>>, done = false, named = false) {
  return events.map(event => (named ? 'event: ' + event.type + '\r\n' : '') +
    'data: ' + JSON.stringify(event) + '\r\n\r\n').join('') +
    (done ? 'data: [DONE]\r\n\r\n' : '')
}

function chunks(text: string, length = 7) {
  const body = Buffer.from(text)
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (let offset = 0; offset < body.length; offset += length) controller.enqueue(body.subarray(offset, offset + length))
      controller.close()
    },
  })
}

function readEvents(text: string) {
  return text.split('\n').filter(line => line.startsWith('data: ') && line !== 'data: [DONE]')
    .map(line => JSON.parse(line.slice(6)))
}

test('sanitizes joined Responses tool arguments with API keys and persona secrets while preserving order', async () => {
  const events = [
    { type: 'response.output_item.added', output_index: 0, item: { type: 'function_call', arguments: '{"status":"ready",' } },
    { type: 'response.function_call_arguments.delta', output_index: 0, delta: '"note":"' + left },
    { type: 'response.output_text.delta', output_index: 1, delta: 'Keep this café text with ' + pLeft },
    { type: 'response.function_call_arguments.delta', output_index: 0, delta: right + '","leaked":"' + pLeft },
    { type: 'response.output_text.delta', output_index: 1, delta: pRight + ' safely.' },
    { type: 'response.function_call_arguments.delta', output_index: 0, delta: pRight + '","cookie":"inert-cookie-fixture"}' },
    {
      type: 'response.function_call_arguments.done',
      output_index: 0,
      arguments: JSON.stringify({
        status: 'ready', note: key, leaked: personaSecret, cookie: 'inert-cookie-fixture',
      }),
    },
    { type: 'response.completed', response: { status: 'completed' } },
  ]
  const safe = await new Response(
    sanitizeProviderStream(chunks(sse(events, true)), key, 'responses', { secrets: personaSecretsList }),
  ).text()
  const output = readEvents(safe)
  assert.deepEqual(output.map(event => event.type), events.map(event => event.type))
  assert.equal(output[2].delta + output[4].delta, 'Keep this café text with [persona:tenant_a:secret] safely.')
  assert.ok(![left, right, pLeft, pRight, personaSecret, 'inert-cookie-fixture'].some(secret => safe.includes(secret)))
  const expected = { status: 'ready', note: marker, leaked: '[persona:tenant_a:secret]', cookie: marker }
  assert.deepEqual(JSON.parse(output[0].item.arguments + output[1].delta + output[3].delta + output[5].delta), expected)
  assert.deepEqual(JSON.parse(output[6].arguments), expected)
  assert.ok(safe.endsWith('data: [DONE]\n\n'))
})

test('sanitizes Messages tool arguments and persona secrets without altering unrelated blocks', async () => {
  const events = [
    { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"status":"ready","note":"' + left } },
    { type: 'content_block_delta', index: 1, delta: { type: 'text_delta', text: 'keep ' + pLeft } },
    { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: right + '","p":"' + pLeft } },
    { type: 'content_block_delta', index: 1, delta: { type: 'text_delta', text: pRight } },
    { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: pRight + '"}' } },
    { type: 'content_block_delta', index: 2, delta: { type: 'input_json_delta', partial_json: '{"note":"incomplete' } },
    { type: 'message_stop' },
  ]
  const wire = sse(events, false, true).replaceAll('\r\n', '\r')
  const safe = await new Response(
    sanitizeProviderStream(chunks(wire), key, 'messages', personaSecretsList),
  ).text()
  const output = readEvents(safe)
  assert.equal(output[1].delta.text + output[3].delta.text, 'keep [persona:tenant_a:secret]')
  assert.deepEqual(
    JSON.parse(output[0].delta.partial_json + output[2].delta.partial_json + output[4].delta.partial_json),
    { status: 'ready', note: marker, p: '[persona:tenant_a:secret]' },
  )
  assert.equal(output[5].delta.partial_json, '{}')
  assert.ok(![left, right, pLeft, pRight, personaSecret].some(secret => safe.includes(secret)))
})

function responsesTurn(textA = prefix + left, textB = right + ' ' + pLeft, textC = pRight + suffix) {
  const item = { type: 'message', id: 'msg_local_fixture', role: 'assistant' }
  return sse([
    { type: 'response.output_item.added', output_index: 0, item: { ...item, content: [], status: 'in_progress' } },
    { type: 'response.output_text.delta', output_index: 0, delta: textA },
    { type: 'response.output_text.delta', output_index: 0, delta: textB },
    { type: 'response.output_text.delta', output_index: 0, delta: textC },
    {
      type: 'response.output_item.done',
      output_index: 0,
      item: {
        ...item,
        content: [
          { type: 'output_text', text: textA },
          { type: 'output_text', text: textB },
          { type: 'output_text', text: textC },
        ],
        status: 'completed',
      },
    },
    {
      type: 'response.completed',
      response: {
        id: 'resp_local_fixture',
        status: 'completed',
        output: [],
        usage: { input_tokens: 1200, output_tokens: 400, total_tokens: 1600 },
      },
    },
  ], true)
}

function messagesTurn() {
  return sse([
    {
      type: 'message_start',
      message: {
        id: 'msg_local_fixture',
        type: 'message',
        role: 'assistant',
        model: 'synthetic',
        content: [],
        usage: { input_tokens: 1200, output_tokens: 0 },
      },
    },
    { type: 'content_block_start', index: 0, content_block: { type: 'text', text: prefix + left } },
    { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: right + ' ' + pLeft } },
    { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: pRight + suffix } },
    { type: 'content_block_stop', index: 0 },
    { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 400 } },
    { type: 'message_stop' },
  ], false, true)
}

for (const protocol of ['responses', 'messages'] as const) {
  test(`keeps split ${protocol} API keys and persona secrets out of recorded turns and Pi Durable sessions`, async t => {
    const directory = await mkdtemp(join(tmpdir(), 'kovo-provider-redaction-'))
    const server = createServer((request, response) => {
      request.resume()
      response.writeHead(200, { 'Content-Type': 'text/event-stream' })
      response.end(protocol === 'responses' ? responsesTurn() : messagesTurn())
    }).listen(0, '127.0.0.1')
    t.after(async () => {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
      await rm(directory, { recursive: true, force: true })
    })
    await once(server, 'listening')
    const address = server.address()
    assert.ok(address && typeof address !== 'string')
    const recorded: ProviderCall[] = []
    const usages: UsageEvent[] = []
    const answer = await agentTurn({
      directory,
      sessionId: 'local-test',
      requestId: 'offline-review',
      prompt: 'Summarize the supplied observation.',
      settings: { endpoint: 'http://127.0.0.1:' + address.port, model: 'synthetic', protocol, key },
      secrets: personaSecretsList,
      scenario: 'coordinator',
      signal: AbortSignal.timeout(8_000),
      record: call => recorded.push(call),
      onUsage: usage => usages.push(usage),
    })
    assert.equal(answer, prefix + marker + ' [persona:tenant_a:secret]' + suffix)
    assert.equal(recorded.length, 1)
    assert.equal(usages.length, 1)
    assert.equal(usages[0].inputTokens, 1200)
    assert.equal(usages[0].outputTokens, 400)
    assert.ok(usages[0].costUsd > 0)
    assert.ok(![left, right, pLeft, pRight, personaSecret].some(secret => JSON.stringify(recorded).includes(secret)))
    const sessions = join(directory, 'agent-sessions')
    const files = await readdir(sessions)
    assert.ok(files.some(file => file.endsWith('.sqlite')))
    for (const file of files) {
      const saved = await readFile(join(sessions, file))
      assert.ok(![key, left, right, personaSecret, pLeft, pRight].some(secret => saved.includes(secret)))
    }
  })
}

test('releases a sanitized turn at its terminal event while the upstream stream remains open', async () => {
  const entered = Promise.withResolvers<ReadableStreamDefaultController<Uint8Array>>()
  const input = new ReadableStream<Uint8Array>({ start: controller => entered.resolve(controller) })
  const controller = await entered.promise
  const reader = sanitizeProviderStream(input, key, 'responses').getReader()
  let delivered = false
  const output = reader.read().then(result => { delivered = true; return result })
  try {
    controller.enqueue(Buffer.from(sse([{ type: 'response.output_text.delta', output_index: 0, delta: left }])))
    await nextTurn()
    assert.equal(delivered, false)
    controller.enqueue(Buffer.from(sse([
      { type: 'response.output_text.delta', output_index: 0, delta: right },
      { type: 'response.completed' },
    ])))
    const first = await output
    assert.equal(first.done, false)
    assert.equal(readEvents(Buffer.from(first.value!).toString())[0].delta, marker)
  } finally {
    await reader.cancel()
  }
})

test('enforces v2 16 MiB default stream limit and rejects invalid or oversized data safely', async () => {
  assert.equal(defaultStreamResponseLimit, 16 * 1024 * 1024)
  await assert.rejects(
    new Response(sanitizeProviderStream(chunks('data: invalid-' + key + '\n\n'), key, 'responses')).text(),
    error => error instanceof Error && error.message === 'The model returned invalid streaming data.',
  )
  const mismatched = 'event: message_start\n' + sse([{ type: 'content_block_delta' }])
  await assert.rejects(
    new Response(sanitizeProviderStream(chunks(mismatched), key, 'messages')).text(),
    /mismatched Messages event/,
  )
  // Custom low responseLimit enforces byte cap without leaking contents
  await assert.rejects(
    new Response(sanitizeProviderStream(chunks('x'.repeat(8 * 1024 + 1), 1024), key, 'responses', { responseLimit: 8 * 1024 })).text(),
    /response exceeded Kovo(?: Hunter)?’s size limit/,
  )
})

test('classifies 429 quota exhaustion as 402 hard failure vs transient RPM rate limits', () => {
  assert.equal(isQuotaBody('{"error":{"message":"You exceeded your current quota, please check billing."}}'), true)
  assert.equal(isQuotaBody('{"error":{"message":"Insufficient credits on account balance"}}'), true)
  assert.equal(isQuotaBody('{"error":{"message":"Requests per minute rate limit exceeded, retry after 2s"}}'), false)

  const quotaErr = classifyProviderFailure('The provider quota or credit balance was exhausted.')
  assert.equal(quotaErr?.kind, 'quota')
  assert.equal(quotaErr?.hard, true)
  const authErr = classifyProviderFailure('The provider rejected the API key.')
  assert.equal(authErr?.kind, 'auth')
  assert.equal(authErr?.hard, true)
  const rateLimitErr = classifyProviderFailure('The provider rate limit was reached.')
  assert.equal(rateLimitErr?.kind, 'rate_limited')
  assert.equal(rateLimitErr?.hard, false)
  const serverErr = classifyProviderFailure('The model provider returned HTTP 503.')
  assert.equal(serverErr?.kind, 'server')
  assert.equal(serverErr?.hard, false)
  assert.equal(classifyProviderFailure('The operation was aborted by user'), null)
})

test('multi-profile LLM failover pool handles 429->402 quota circuit breaking, context filtering, and safe-window failover', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'kovo-failover-pool-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const storage = new Store(directory)
  t.after(() => storage.close())

  let primaryCalls = 0
  let backupCalls = 0
  let primaryMode: 'quota_429' | 'midstream_error' | 'ok' = 'quota_429'

  const primaryServer = createServer((req, res) => {
    req.resume()
    primaryCalls += 1
    if (primaryMode === 'quota_429') {
      res.writeHead(429, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ error: { message: 'You exceeded your current quota and credit balance.' } }))
      return
    }
    if (primaryMode === 'midstream_error') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' })
      // Emit a real delta first (leaving safe window), then fail mid-stream
      res.write(sse([
        { type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: 'msg_1', role: 'assistant', content: [], status: 'in_progress' } },
        { type: 'response.output_text.delta', output_index: 0, delta: 'partial-token ' },
        { type: 'response.failed', response: { id: 'resp_fail', status: 'failed', error: { message: 'The model provider returned HTTP 503.' } } },
      ]))
      res.end()
      return
    }
    res.writeHead(200, { 'Content-Type': 'text/event-stream' })
    res.end(responsesTurn('Primary ', 'profile ', 'succeeded.'))
  }).listen(0, '127.0.0.1')

  const backupServer = createServer((req, res) => {
    req.resume()
    backupCalls += 1
    res.writeHead(200, { 'Content-Type': 'text/event-stream' })
    res.end(responsesTurn('Backup ', 'profile ', 'answered.'))
  }).listen(0, '127.0.0.1')

  t.after(async () => {
    primaryServer.closeAllConnections()
    backupServer.closeAllConnections()
    await Promise.all([
      new Promise<void>(resolve => primaryServer.close(() => resolve())),
      new Promise<void>(resolve => backupServer.close(() => resolve())),
    ])
  })

  await Promise.all([once(primaryServer, 'listening'), once(backupServer, 'listening')])
  const pAddr = primaryServer.address()
  const bAddr = backupServer.address()
  assert.ok(pAddr && typeof pAddr !== 'string' && bAddr && typeof bAddr !== 'string')

  const p1 = await saveModelProfile({
    name: 'Primary High Priority',
    endpoint: `http://127.0.0.1:${pAddr.port}`,
    model: 'primary-model',
    protocol: 'responses',
    key: 'primary-fixture-key-11111',
    priority: 200,
    contextWindow: 64_000,
  }, storage, { skipConnectionCheck: true })

  const p2 = await saveModelProfile({
    name: 'Backup Large Context',
    endpoint: `http://127.0.0.1:${bAddr.port}`,
    model: 'backup-model',
    protocol: 'responses',
    key: 'backup-fixture-key-22222',
    priority: 100,
    contextWindow: 200_000,
  }, storage, { skipConnectionCheck: true })

  // Context window filtering: 100k estimated tokens skips 64k primary and picks 200k backup
  const initialProfiles = privateModelProfiles(storage)
  assert.equal(initialProfiles.length, 2)
  assert.deepEqual(orderProfiles(initialProfiles, 100_000).map(p => p.id), [p2.id])

  // Safe-window failover on 429 quota body -> 402 hard trip -> routes cleanly to backup
  const failures: Array<{ id: string; hard: boolean }> = []
  const successes: string[] = []
  const answer = await agentTurn({
    directory,
    sessionId: 'failover-session',
    requestId: 'failover-1',
    prompt: 'Analyze target.',
    profiles: initialProfiles,
    scenario: 'coordinator',
    signal: AbortSignal.timeout(8_000),
    onProfileFailure: (id, err, hard) => {
      failures.push({ id, hard })
      recordProfileFailure(id, err, hard, storage)
    },
    onProfileSuccess: id => {
      successes.push(id)
      recordProfileSuccess(id, storage)
    },
  })

  assert.equal(answer, 'Backup profile answered.')
  assert.equal(primaryCalls, 1)
  assert.equal(backupCalls, 1)
  assert.deepEqual(failures, [{ id: p1.id, hard: true }])
  assert.deepEqual(successes, [p2.id])

  // Primary circuit breaker is now OPEN in SQLite; next orderProfiles skips it
  const publicProfiles = listModelProfiles(storage)
  assert.equal(publicProfiles.find(p => p.id === p1.id)?.healthState, 'open')
  assert.equal(publicProfiles.find(p => p.id === p2.id)?.healthState, 'closed')
  assert.deepEqual(orderProfiles(privateModelProfiles(storage), 1000).map(p => p.id), [p2.id])

  // Safe-window invariant: once an event is emitted from primary, mid-stream failure must NOT fail over to backup
  recordProfileSuccess(p1.id, storage)
  primaryMode = 'midstream_error'
  const backupBefore = backupCalls
  const { models, model } = providerPool(privateModelProfiles(storage), 'coordinator', {
    signal: AbortSignal.timeout(8_000),
  })
  const stream = models.stream(model, {
    systemPrompt: 'Test safe window.',
    messages: [{ role: 'user', content: 'Stream something.', timestamp: Date.now() }],
    tools: [],
  })
  let sawDelta = false
  for await (const ev of stream) {
    if (ev.type === 'text_delta') sawDelta = true
  }
  const finalRes = await stream.result()
  assert.equal(sawDelta, true)
  assert.equal(finalRes.stopReason, 'error')
  assert.equal(backupCalls, backupBefore, 'Must NOT fail over after emitting stream events (outside safe window).')
})

test('cached input token pricing and editing a profile without re-entering API key', async t => {
  // 1. OpenAI Responses / OpenRouter cached token extraction & billing
  const responsesSse = `data: ${JSON.stringify({
    type: 'response.completed',
    response: {
      usage: {
        input_tokens: 1_000_000,
        input_tokens_details: { cached_tokens: 800_000 },
        output_tokens: 100_000,
      },
    },
  })}\n\n`
  const rUsage = extractUsageFromSse(responsesSse, 'responses')
  assert.deepEqual(rUsage, { inputTokens: 1_000_000, cachedInputTokens: 800_000, outputTokens: 100_000 })
  const rCost = estimateCostUsd({
    endpoint: 'https://openrouter.ai/api/v1',
    model: 'deepseek/deepseek-v4.1-flash-1017',
    protocol: 'responses',
    key: 'sk-test-placeholder',
    inputCostPerMtok: 0.15,
    cachedInputCostPerMtok: 0.003,
    outputCostPerMtok: 0.60,
  }, rUsage.inputTokens, rUsage.outputTokens, rUsage.cachedInputTokens)
  // 200k uncached * $0.15/M = $0.03 + 800k cached * $0.003/M = $0.0024 + 100k out * $0.60/M = $0.06 -> $0.0924
  assert.ok(Math.abs(rCost - 0.0924) < 1e-9, `Expected $0.0924, got ${rCost}`)

  // 2. Anthropic Messages cached token extraction (input_tokens excludes cache_read_input_tokens)
  const messagesSse = `data: ${JSON.stringify({
    type: 'message_start',
    message: { usage: { input_tokens: 200_000, cache_read_input_tokens: 800_000, output_tokens: 0 } },
  })}\ndata: ${JSON.stringify({
    type: 'message_delta',
    usage: { output_tokens: 100_000 },
  })}\n\n`
  const mUsage = extractUsageFromSse(messagesSse, 'messages')
  assert.deepEqual(mUsage, { inputTokens: 1_000_000, cachedInputTokens: 800_000, outputTokens: 100_000 })

  // 3. Editing an existing profile with blank key preserves the stored 0600 credential & skips redundant check
  const directory = await mkdtemp(join(tmpdir(), 'kovo-model-edit-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const storage = new Store(directory)
  t.after(() => storage.close())

  const saved = await saveModelProfile({
    name: 'OpenRouter DeepSeek V4.1 Flash',
    endpoint: 'https://openrouter.ai/api/v1',
    model: 'deepseek/deepseek-v4.1-flash-1017',
    protocol: 'responses',
    key: 'sk-or-v1-original-secret-value',
    priority: 100,
    enabled: true,
    contextWindow: 131_072,
    maxTokens: 16_384,
    thinkingLevel: 'medium',
    inputCostPerMtok: 0.25,
    cachedInputCostPerMtok: 0.003,
    outputCostPerMtok: 0.90,
  }, storage, { skipConnectionCheck: true })

  // Update contextWindow & costs WITHOUT re-entering API key (and WITHOUT skipConnectionCheck!)
  await saveModelProfile({
    id: saved.id,
    name: 'OpenRouter DeepSeek V4.1 Flash',
    endpoint: 'https://openrouter.ai/api/v1',
    model: 'deepseek/deepseek-v4.1-flash-1017',
    protocol: 'responses',
    key: '',
    priority: 100,
    enabled: true,
    contextWindow: 1_048_576,
    maxTokens: 16_384,
    thinkingLevel: 'medium',
    inputCostPerMtok: 0.15,
    cachedInputCostPerMtok: 0.003,
    outputCostPerMtok: 0.60,
  }, storage)

  const priv = privateModelProfiles(storage)
  assert.equal(priv.length, 1)
  assert.equal(priv[0].key, 'sk-or-v1-original-secret-value')
  assert.equal(priv[0].contextWindow, 1_048_576)
  assert.equal(priv[0].inputCostPerMtok, 0.15)
  assert.equal(priv[0].cachedInputCostPerMtok, 0.003)
  assert.equal(priv[0].outputCostPerMtok, 0.60)
})
