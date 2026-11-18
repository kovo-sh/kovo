import { isDeepStrictEqual } from 'node:util'
import { once } from 'node:events'
import { readFileSync, readdirSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { comparableRequest } from '../scripts/fixture-record.ts'
import type { ProviderCall } from '../src/server/provider.ts'
import { fixtureCredential, healthy, primary, unavailable } from './scenarios.ts'

type Recording = { scenario: string; protocol: string; calls: ProviderCall[] }
const captures = new URL('./fixtures/', import.meta.url)
const recordings = readdirSync(captures)
  .filter(file => file.startsWith('openrouter-') && file.endsWith('.json'))
  .map(file => JSON.parse(readFileSync(new URL(file, captures), 'utf8')) as Recording)
const sensitiveFixtureValue = 'private-synthetic-cookie-value-8347'

function withOutputLimit(body: string) {
  const events = body.split('\n\n').flatMap(frame => {
    const data = frame.split('\n').find(line => line.startsWith('data: {'))
    return data ? [{ frame, event: JSON.parse(data.slice(6)) }] : []
  })
  const toolIndex = events.findIndex(({ event }) => event.type === 'response.output_item.added' && event.item?.type === 'function_call')
  const completed = events.find(({ event }) => event.type === 'response.completed')?.event
  if (toolIndex < 0 || !completed) throw new Error('The output-limit scenario requires a recorded tool turn.')
  const { response, sequence_number } = completed
  return [...events.slice(0, toolIndex).map(({ frame }) => frame), 'data: ' + JSON.stringify({
    type: 'response.incomplete', sequence_number,
    response: {
      ...response, status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' },
      output: response.output.filter((item: { type: string }) => item.type === 'reasoning'),
    },
  })].join('\n\n')
}

export async function fixtureServer(options: { hold?: string; scenes: string[]; truncate?: string }) {
  const requested: string[] = []
  const accepted: string[] = []
  const unexpected: string[] = []
  const pending: ServerResponse[] = []
  const withheld = Promise.withResolvers<void>()
  let hold = options.hold
  const selected = recordings.filter(fixture => options.scenes.includes(fixture.scenario))
  const responseList = selected.flatMap(recording => recording.calls.map((call, turn) => ({
    ...call, name: recording.scenario + ':' + recording.protocol + ':' + turn, seen: false,
  })))
  function sendPage(target: string, response: ServerResponse) {
    const capture = [primary, unavailable, healthy].find(item => item.origin + '/' === target)
    if (!capture) {
      unexpected.push('Unexpected target: ' + target)
      response.writeHead(404).end('Fixture missing')
      return
    }
    response.writeHead(capture.status, {
      'Content-Type': capture.mediaType,
      'Set-Cookie': 'sid=' + sensitiveFixtureValue,
      ...(capture.transportMaxAge !== null ? { 'Strict-Transport-Security': 'max-age=' + capture.transportMaxAge } : {}),
    }).end('Prepared response with local-only data. ' + sensitiveFixtureValue)
  }

  async function serve(request: IncomingMessage, response: ServerResponse) {
    if (request.method === 'POST') {
      if (request.headers.authorization !== 'Bearer ' + fixtureCredential && request.headers['x-api-key'] !== fixtureCredential) {
        response.writeHead(401, { 'Content-Type': 'application/json' }).end('{"error":{"message":"Invalid test key"}}')
        return
      }
      const chunks = []
      for await (const chunk of request) chunks.push(Buffer.from(chunk))
      const payload = JSON.parse(Buffer.concat(chunks).toString('utf8'))
      const normalized = comparableRequest(payload)
      const endpoint = new URL(request.url ?? '/', 'http://127.0.0.1').pathname
      const match = responseList.find(call => call.endpoint === endpoint && !call.seen &&
        isDeepStrictEqual(normalized, comparableRequest(call.request)))
      if (!match) {
        const candidate = responseList.find(call => call.endpoint === endpoint && !call.seen)
        unexpected.push(JSON.stringify({ endpoint, actual: normalized, expected: candidate && comparableRequest(candidate.request) }))
        response.writeHead(422, { 'Content-Type': 'application/json' }).end('{"error":{"message":"No recording matched the request"}}')
        return
      }
      const body = options.truncate && match.name === `${options.truncate}:responses:0` ? withOutputLimit(match.body) : match.body
      match.seen = true
      accepted.push(match.name)
      response.writeHead(match.status, { 'Content-Type': match.contentType })
      // Keep streaming boundaries even when multiple calls are replayed in parallel.
      for (const event of body.split('\n\n').filter(Boolean)) {
        if (response.destroyed) return
        response.write(event + '\n\n')
        await new Promise(resolve => setImmediate(resolve))
      }
      response.end()
      return
    }
    const target = request.headers['x-guardian-fixture-target']
    if (typeof target !== 'string') {
      response.writeHead(400).end('Expected a synthetic target')
      return
    }
    requested.push(target)
    if (target === hold) {
      pending.push(response)
      withheld.resolve()
      return
    }
    sendPage(target, response)
  }

  const server = createServer((request, response) => {
    void serve(request, response).catch(() => {
      unexpected.push('Could not handle the fixture request.')
      if (!response.headersSent) response.writeHead(500)
      response.end()
    })
  }).listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Could not allocate a fixture port.')
  return {
    origin: `http://127.0.0.1:${address.port}`,
    requested,
    accepted,
    unexpected,
    withheld: withheld.promise,
    sensitiveFixtureValue,
    release() {
      const target = hold
      hold = undefined
      if (target) for (const response of pending.splice(0)) {
        if (!response.destroyed) sendPage(target, response)
      }
    },
    close() {
      server.closeAllConnections()
      return new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}
