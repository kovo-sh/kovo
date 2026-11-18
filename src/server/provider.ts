import { createModels, createProvider } from '@earendil-works/pi-ai/models'
import { stream as responses, streamSimple as simpleResponses } from '@earendil-works/pi-ai/api/openai-responses'
import { stream as messages, streamSimple as simpleMessages } from '@earendil-works/pi-ai/api/anthropic-messages'
import type { Api, Model, ProviderStreams } from '@earendil-works/pi-ai'
import { obj, str } from '@earendil-works/pi-schema'
import { DEFAULT_PROVIDER } from '../domain.ts'
import type { ProviderSettings } from '../domain.ts'
import { redactProviderText, sanitizeProviderStream, sanitizeProviderValue } from './provider-stream.ts'
import { redact } from './redact.ts'

type Protocol = 'openai-responses' | 'anthropic-messages'
const modelTokenLimit = 384
const providerId = 'guardian'

export type ProviderCall = {
  scenario: string
  endpoint: string
  request: Record<string, unknown>
  status: number
  contentType: string
  body: string
}
type CallRecorder = (call: ProviderCall) => void

function transport(settings: ProviderSettings, scenario: string, signal?: AbortSignal, record?: CallRecorder) {
  const endpoint = settings.protocol === 'responses' ? settings.endpoint + '/responses'
    : settings.endpoint.replace(/\/v1$/, '') + '/v1/messages'
  let count = 0
  const send: typeof fetch = async (input, init) => {
    if (++count > 3) throw new Error('The model call budget for this operation was reached.')
    const request = new Request(input, init)
    const actual = new URL(request.url)
    const beta = settings.protocol === 'messages' && actual.search === '?beta=true'
    if (beta) actual.search = ''
    if (actual.href !== endpoint || request.method !== 'POST') throw new Error('Unexpected model endpoint.')
    if (process.env.GUARDIAN_OFFLINE === '1' && actual.hostname !== '127.0.0.1') {
      throw new Error('Offline mode requires a loopback model fixture endpoint.')
    }
    const headers = new Headers(request.headers)
    if (new URL(endpoint).origin === 'https://openrouter.ai') {
      headers.delete('x-api-key')
      headers.set('authorization', 'Bearer ' + settings.key)
    }

    const raw = await request.text()
    if (Buffer.byteLength(raw) > 80 * 1024) throw new Error('The model request exceeded Guardian’s size limit.')
    const payload = JSON.parse(raw) as Record<string, unknown>
    const abort = AbortSignal.any([request.signal, AbortSignal.timeout(35_000), ...(signal ? [signal] : [])])
    const response = await fetch(beta ? endpoint + '?beta=true' : endpoint, {
      method: 'POST', headers, body: raw, redirect: 'error', signal: abort,
    })
    const contentType = response.headers.get('content-type') ?? 'application/json'
    const recordResponse = record && ((body: string) => record({
      scenario, endpoint: redactProviderText(new URL(endpoint).pathname, settings.key),
      request: sanitizeProviderValue(payload, settings.key) as Record<string, unknown>,
      status: response.status, contentType: redactProviderText(contentType, settings.key), body,
    }))
    if (!response.ok) {
      await response.body?.cancel()
      const message = response.status === 401 || response.status === 403
        ? 'The provider rejected the API key.' : response.status === 404
          ? 'The provider endpoint or model was not found.' : response.status === 429
            ? 'The provider rate limit was reached.' : `The model provider returned HTTP ${response.status}.`
      const error = JSON.stringify({ error: { message } })
      recordResponse?.(error)
      return new Response(error, { status: response.status, headers: { 'content-type': 'application/json' } })
    }
    if (!response.body || !contentType.toLowerCase().includes('text/event-stream')) {
      await response.body?.cancel()
      throw new Error('The provider did not return a streaming response.')
    }
    const stream = sanitizeProviderStream(response.body, settings.key, settings.protocol)
    let body: BodyInit = stream
    if (recordResponse) {
      body = await new Response(stream).text()
      recordResponse(body)
    }
    return new Response(body, {
      status: response.status, headers: { 'content-type': 'text/event-stream' },
    })
  }
  return send
}

export function provider(settings: ProviderSettings, scenario: string, signal?: AbortSignal, record?: CallRecorder) {
  const api: Protocol = settings.protocol === 'responses' ? 'openai-responses' : 'anthropic-messages'
  const model: Model<Protocol> = {
    id: settings.model,
    name: settings.model,
    provider: providerId,
    api,
    baseUrl: settings.protocol === 'messages' ? settings.endpoint.replace(/\/v1$/, '') : settings.endpoint,
    input: ['text'],
    // The Messages adapter sends the disabled setting for reasoning-capable models.
    reasoning: api === 'anthropic-messages' && settings.model === DEFAULT_PROVIDER.model,
    contextWindow: 24_000,
    maxTokens: modelTokenLimit,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
  }
  const send = transport(settings, scenario, signal, record)
  const connection = scenario === 'connection'
  const chooseEvidenceTool = (transcript: { messages: { role: string }[] }) =>
    (scenario === 'worker-analysis' || scenario === 'response-analysis') && transcript.messages.at(-1)?.role === 'user'
  const options = { fetch: send, maxTokens: modelTokenLimit, maxRetries: 0, timeoutMs: 35_000 }
  const implementation: ProviderStreams = api === 'openai-responses' ? {
    stream: (selected, transcript, streamOptions) => responses(selected as Model<'openai-responses'>, transcript, {
      ...streamOptions, ...options, ...(connection ? { toolChoice: 'required' as const } : {}),
    }),
    streamSimple: (selected, transcript, streamOptions) =>
      chooseEvidenceTool(transcript)
        ? responses(selected as Model<'openai-responses'>, transcript, { ...streamOptions, ...options, toolChoice: 'required' })
        : simpleResponses(selected as Model<'openai-responses'>, transcript, { ...streamOptions, ...options }),
  } : {
    stream: (selected, transcript, streamOptions) => messages(selected as Model<'anthropic-messages'>, transcript, {
      ...streamOptions, ...options, thinkingEnabled: false,
      ...(connection ? { toolChoice: { type: 'tool' as const, name: 'guardian_connection' } } : {}),
    }),
    streamSimple: (selected, transcript, streamOptions) =>
      chooseEvidenceTool(transcript)
        ? messages(selected as Model<'anthropic-messages'>, transcript, {
          ...streamOptions, ...options, thinkingEnabled: false, toolChoice: { type: 'tool', name: 'derive_evidence' },
        })
        : simpleMessages(selected as Model<'anthropic-messages'>, transcript, { ...streamOptions, ...options }),
  }
  const models = createModels({ identity: { attribution: null } })
  models.setProvider(createProvider<Api>({
    id: providerId,
    auth: { apiKey: { name: 'Workspace provider key', resolve: async () => ({ auth: { apiKey: settings.key } }) } },
    api: implementation,
    models: [model],
  }))
  return { models, model }
}

export async function testProvider(settings: ProviderSettings, record?: CallRecorder) {
  const { models, model } = provider(settings, 'connection', undefined, record)
  const stream = models.stream(model, {
    systemPrompt: 'Guardian connection test. Call guardian_connection with status ready. Do not add prose.',
    messages: [{ role: 'user', content: 'Check the Guardian connection.', timestamp: Date.now() }],
    tools: [{
      name: 'guardian_connection',
      description: 'Return status ready to confirm this synthetic connection test.',
      parameters: obj({ status: str() }),
    }],
  })
  let toolEvents = false
  for await (const event of stream) {
    if (event.type === 'toolcall_delta' || event.type === 'toolcall_end') toolEvents = true
  }
  const result = await stream.result()
  if (result.stopReason === 'error' || result.stopReason === 'aborted') {
    const error = redact(result.errorMessage ?? '').slice(0, 350)
    const match = error.match(/The (?:provider rejected the API key|provider endpoint or model was not found|provider rate limit was reached|model provider returned HTTP \d+)\./)
    throw new Error(match?.[0] ?? 'The provider connection failed. Check the base URL, model, key, and protocol.')
  }
  if (!toolEvents || !result.content.some(part => part.type === 'toolCall' && part.name === 'guardian_connection' &&
    part.arguments.status === 'ready')) {
    throw new Error('The model did not return the expected streamed tool call.')
  }
  return { ok: true as const }
}
