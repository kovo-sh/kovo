import type { ProviderSettings } from '../domain.ts'
import { redact } from './redact.ts'

type Fields = Record<string, unknown>
type Fragment = { owner: Fields; field: string; text: string }
type Frame = { lines: string[]; data: Fields | '[DONE]' | undefined }
type Prepared = WeakMap<Fields, Set<string>>

const responseLimit = 768 * 1024
const replacement = '[redacted]'
const credentialField = /^(?:authorization|proxy-authorization|cookie|set-cookie|password|api[_-]?key|token|session[_-]?(?:id|key))$/i
const terminalEvents = new Set(['response.completed', 'response.incomplete', 'response.failed', 'message_stop', 'error'])
const messageEvents = new Set([
  'message_start', 'message_delta', 'message_stop', 'content_block_start', 'content_block_delta', 'content_block_stop',
])
const responseChannels = new Map([
  ['response.output_text.delta', 'text'],
  ['response.refusal.delta', 'text'],
  ['response.reasoning_text.delta', 'thinking'],
  ['response.reasoning_summary_text.delta', 'thinking'],
  ['response.function_call_arguments.delta', 'arguments'],
  ['response.custom_tool_call_input.delta', 'input'],
])
const messageDeltaFields = new Map([
  ['text_delta', 'text'],
  ['thinking_delta', 'thinking'],
  ['signature_delta', 'signature'],
  ['input_json_delta', 'partial_json'],
])

function fields(value: unknown): Fields | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Fields : undefined
}

export function redactProviderText(value: string, key: string) {
  return redact(key ? value.replaceAll(key, replacement) : value)
}

function fragment(owner: Fields | undefined, field: string): Fragment | undefined {
  const text = owner?.[field]
  return owner && typeof text === 'string' ? { owner, field, text } : undefined
}

function redactArguments(value: string, key: string) {
  if (!value.trim()) return value
  let parsed: unknown
  try {
    parsed = JSON.parse(value)
  } catch {
    // Incomplete tool arguments can contain JSON escapes that a partial parser would decode.
    return '{}'
  }
  const safe = JSON.stringify(sanitizeProviderValue(parsed, key))
  return safe === JSON.stringify(parsed) ? value : safe
}

function prepareFragments(items: Fragment[], key: string, prepared: Prepared, json = false) {
  if (!items.length) return
  const joined = items.map(item => item.text).join('')
  const safe = json ? redactArguments(joined, key) : redactProviderText(joined, key)
  let offset = 0
  for (const [index, item] of items.entries()) {
    const end = index === items.length - 1 ? undefined : offset + item.text.length
    item.owner[item.field] = safe.slice(offset, end)
    offset += item.text.length
    if (!prepared.has(item.owner)) prepared.set(item.owner, new Set())
    prepared.get(item.owner)!.add(item.field)
  }
}

export function sanitizeProviderValue(value: unknown, key: string, prepared: Prepared = new WeakMap()): unknown {
  if (typeof value === 'string') return redactProviderText(value, key)
  if (Array.isArray(value)) return value.map(item => sanitizeProviderValue(item, key, prepared))
  const record = fields(value)
  if (!record) return value
  // Responses also supplies completed message snapshots whose text parts are joined by the adapter.
  if (record.type === 'message' && Array.isArray(record.content)) {
    const parts = record.content.flatMap(item => {
      const part = fields(item)
      const text = fragment(part, part?.type === 'refusal' ? 'refusal' : 'text')
      return text ? [text] : []
    })
    prepareFragments(parts, key, prepared)
  }
  return Object.fromEntries(Object.entries(record).map(([name, item]) => {
    const safeName = redactProviderText(name, key)
    if (prepared.get(record)?.has(name)) return [safeName, item]
    if (credentialField.test(name)) return [safeName, replacement]
    if (name === 'arguments' && typeof item === 'string' &&
        (record.type === 'function_call' || record.type === 'response.function_call_arguments.done')) {
      return [safeName, redactArguments(item, key)]
    }
    return [safeName, sanitizeProviderValue(item, key, prepared)]
  }))
}

function prepareDeltas(frames: Frame[], key: string) {
  const groups = new Map<string, { json: boolean; parts: Fragment[] }>()
  function add(protocol: 'responses' | 'messages', index: unknown, channel: string, part: Fragment | undefined) {
    if (!part) return
    const id = JSON.stringify([protocol, index, channel])
    let group = groups.get(id)
    if (!group) {
      group = { json: channel === 'arguments' || channel === 'partial_json', parts: [] }
      groups.set(id, group)
    }
    group.parts.push(part)
  }
  for (const { data } of frames) {
    if (!data || data === '[DONE]') continue
    const type = String(data.type)
    const channel = responseChannels.get(type)
    if (channel) add('responses', data.output_index, channel, fragment(data, 'delta'))
    else if (type === 'response.output_item.added') {
      const item = fields(data.item)
      if (item?.type === 'function_call') add('responses', data.output_index, 'arguments', fragment(item, 'arguments'))
      if (item?.type === 'custom_tool_call') add('responses', data.output_index, 'input', fragment(item, 'input'))
    } else if (type === 'content_block_delta') {
      const delta = fields(data.delta)
      const field = messageDeltaFields.get(String(delta?.type))
      if (field) add('messages', data.index, field, fragment(delta, field))
    } else if (type === 'content_block_start') {
      const block = fields(data.content_block)
      for (const field of ['text', 'thinking', 'signature']) add('messages', data.index, field, fragment(block, field))
    }
  }
  const prepared: Prepared = new WeakMap()
  for (const group of groups.values()) prepareFragments(group.parts, key, prepared, group.json)
  return prepared
}

function isData(line: string) {
  return line === 'data' || line.startsWith('data:')
}

function readFrame(text: string, protocol: ProviderSettings['protocol']): Frame {
  const lines = text.split('\n')
  const values = lines.filter(isData).map(line => line.slice(5).replace(/^ /, ''))
  if (!values.length) return { lines, data: undefined }
  const raw = values.join('\n')
  if (raw === '[DONE]') return { lines, data: raw }
  let data: Fields | undefined
  try { data = fields(JSON.parse(raw)) } catch { /* Keep the provider's payload out of parse errors. */ }
  if (!data) throw new Error('The model returned invalid streaming data.')
  if (protocol === 'messages') {
    const event = lines.findLast(line => line === 'event' || line.startsWith('event:'))?.slice(6).replace(/^ /, '') ?? ''
    if ((messageEvents.has(event) || messageEvents.has(String(data.type))) && data.type !== event) {
      throw new Error('The model returned a mismatched Messages event.')
    }
  }
  return { lines, data }
}

export function sanitizeProviderStream(body: ReadableStream<Uint8Array>, key: string, protocol: ProviderSettings['protocol']) {
  let pending = ''
  let size = 0
  let finished = false
  let trailingCr = false
  const frames: Frame[] = []
  const decoder = new TextDecoder()
  const encoder = new TextEncoder()
  type Output = TransformStreamDefaultController<Uint8Array>

  function emit(controller: Output) {
    const prepared = prepareDeltas(frames, key)
    for (const frame of frames.splice(0)) {
      const first = frame.lines.findIndex(isData)
      const safe = frame.data === '[DONE]' ? '[DONE]' : JSON.stringify(sanitizeProviderValue(frame.data, key, prepared))
      const lines = frame.lines.flatMap((line, index) => {
        if (!isData(line)) return [redactProviderText(line, key)]
        return index === first ? ['data: ' + safe] : []
      })
      controller.enqueue(encoder.encode(lines.join('\n') + '\n\n'))
    }
  }

  function push(text: string, controller: Output) {
    const frame = readFrame(text, protocol)
    if (finished && frame.data && frame.data !== '[DONE]') {
      throw new Error('The model returned data after the turn ended.')
    }
    frames.push(frame)
    if (frame.data === '[DONE]' || terminalEvents.has(String(frame.data?.type))) finished = true
    // The adapter can persist partial output. Release frames after checking the assembled strings.
    if (finished) emit(controller)
  }

  function append(decoded: string, controller: Output, eof = false) {
    const text = (trailingCr ? '\r' : '') + decoded
    trailingCr = !eof && text.endsWith('\r')
    pending += (trailingCr ? text.slice(0, -1) : text).replace(/\r\n?/g, '\n')
    let boundary: number
    while ((boundary = pending.indexOf('\n\n')) !== -1) {
      const frame = pending.slice(0, boundary)
      pending = pending.slice(boundary + 2)
      push(frame, controller)
    }
  }

  return body.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      size += chunk.byteLength
      if (size > responseLimit) throw new Error('The model response exceeded Guardian’s size limit.')
      append(decoder.decode(chunk, { stream: true }), controller)
    },
    flush(controller) {
      append(decoder.decode(), controller, true)
      if (pending.trim()) push(pending, controller)
      emit(controller)
    },
  }))
}
