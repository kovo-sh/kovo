import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { setImmediate as nextTurn } from 'node:timers/promises'
import { agentTurn } from '../src/server/agent-session.ts'
import type { ProviderCall } from '../src/server/provider.ts'
import { sanitizeProviderStream } from '../src/server/provider-stream.ts'

const key = 'inert-provider-fixture-secret-z68'
const left = key.slice(0, 16)
const right = key.slice(16)
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

test('sanitizes joined Responses tool arguments while preserving event order and unrelated output', async () => {
  const events = [
    { type: 'response.output_item.added', output_index: 0, item: { type: 'function_call', arguments: '{"status":"ready",' } },
    { type: 'response.function_call_arguments.delta', output_index: 0, delta: '"note":"' + left },
    { type: 'response.output_text.delta', output_index: 1, delta: 'Keep this café text.' },
    { type: 'response.function_call_arguments.delta', output_index: 0, delta: right + '","cookie":"inert-cookie-fixture"}' },
    { type: 'response.function_call_arguments.done', output_index: 0, arguments: JSON.stringify({
      status: 'ready', note: key, cookie: 'inert-cookie-fixture',
    }) },
    { type: 'response.completed', response: { status: 'completed' } },
  ]
  const safe = await new Response(sanitizeProviderStream(chunks(sse(events, true)), key, 'responses')).text()
  const output = readEvents(safe)
  assert.deepEqual(output.map(event => event.type), events.map(event => event.type))
  assert.equal(output[2].delta, events[2].delta)
  assert.ok(![left, right, 'inert-cookie-fixture'].some(secret => safe.includes(secret)))
  const expected = { status: 'ready', note: marker, cookie: marker }
  assert.deepEqual(JSON.parse(output[0].item.arguments + output[1].delta + output[3].delta), expected)
  assert.deepEqual(JSON.parse(output[4].arguments), expected)
  assert.ok(safe.endsWith('data: [DONE]\n\n'))
})

test('sanitizes Messages tool arguments without altering text from a different block', async () => {
  const events = [
    { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"status":"ready","note":"' + left } },
    { type: 'content_block_delta', index: 1, delta: { type: 'text_delta', text: 'keep' } },
    { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: right + '"}' } },
    { type: 'content_block_delta', index: 2, delta: { type: 'input_json_delta', partial_json: '{"note":"incomplete' } },
    { type: 'message_stop' },
  ]
  const wire = sse(events, false, true).replaceAll('\r\n', '\r')
  const safe = await new Response(sanitizeProviderStream(chunks(wire), key, 'messages')).text()
  const output = readEvents(safe)
  assert.equal(output[1].delta.text, 'keep')
  assert.deepEqual(JSON.parse(output[0].delta.partial_json + output[2].delta.partial_json), { status: 'ready', note: marker })
  assert.equal(output[3].delta.partial_json, '{}')
  assert.ok(![left, right].some(secret => safe.includes(secret)))
})

function responsesTurn() {
  const item = { type: 'message', id: 'msg_local_fixture', role: 'assistant' }
  return sse([
    { type: 'response.output_item.added', output_index: 0, item: { ...item, content: [], status: 'in_progress' } },
    { type: 'response.output_text.delta', output_index: 0, delta: prefix + left },
    { type: 'response.output_text.delta', output_index: 0, delta: right + suffix },
    { type: 'response.output_item.done', output_index: 0, item: { ...item, content: [
      { type: 'output_text', text: prefix + left }, { type: 'output_text', text: right + suffix },
    ], status: 'completed' } },
    { type: 'response.completed', response: { id: 'resp_local_fixture', status: 'completed', output: [], usage: {
      input_tokens: 1, output_tokens: 2, total_tokens: 3,
    } } },
  ], true)
}

function messagesTurn() {
  return sse([
    { type: 'message_start', message: { id: 'msg_local_fixture', type: 'message', role: 'assistant', model: 'synthetic',
      content: [], usage: { input_tokens: 1, output_tokens: 0 } } },
    { type: 'content_block_start', index: 0, content_block: { type: 'text', text: prefix + left } },
    { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: right + suffix } },
    { type: 'content_block_stop', index: 0 },
    { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 2 } },
    { type: 'message_stop' },
  ], false, true)
}

for (const protocol of ['responses', 'messages'] as const) {
  test(`keeps split ${protocol} credentials out of recorded turns and durable sessions`, async t => {
    const directory = await mkdtemp(join(tmpdir(), 'guardian-provider-redaction-'))
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
    const answer = await agentTurn({
      directory, sessionId: 'local-test', requestId: 'offline-review', prompt: 'Summarize the supplied observation.',
      settings: { endpoint: 'http://127.0.0.1:' + address.port, model: 'synthetic', protocol, key },
      scenario: 'coordinator', signal: AbortSignal.timeout(8_000), record: call => recorded.push(call),
    })
    assert.equal(answer, prefix + marker + suffix)
    assert.equal(recorded.length, 1)
    assert.ok(![left, right].some(secret => JSON.stringify(recorded).includes(secret)))
    const sessions = join(directory, 'agent-sessions')
    const files = await readdir(sessions)
    assert.ok(files.some(file => file.endsWith('.sqlite')))
    for (const file of files) {
      const saved = await readFile(join(sessions, file))
      assert.ok(![key, left, right].some(secret => saved.includes(secret)))
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

test('reports invalid or oversized streaming data without including its contents', async () => {
  await assert.rejects(new Response(sanitizeProviderStream(chunks('data: invalid-' + key + '\n\n'), key, 'responses')).text(),
    error => error instanceof Error && error.message === 'The model returned invalid streaming data.')
  const mismatched = 'event: message_start\n' + sse([{ type: 'content_block_delta' }])
  await assert.rejects(new Response(sanitizeProviderStream(chunks(mismatched), key, 'messages')).text(),
    /mismatched Messages event/)
  await assert.rejects(new Response(sanitizeProviderStream(chunks('x'.repeat(768 * 1024 + 1), 1024), key, 'responses')).text(),
    /response exceeded Guardian’s size limit/)
})
