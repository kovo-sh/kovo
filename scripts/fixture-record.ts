import { mkdirSync, writeFileSync } from 'node:fs'
import { DEFAULT_PROVIDER } from '../src/domain.ts'
import type { ProviderCall } from '../src/server/provider.ts'

const valueFields = new Set(['prompt_cache_key', 'session_id', 'safety_identifier'])
const idPattern = /\b(resp|call|fc|msg|toolu|gen|rs)_[A-Za-z0-9_-]{10,}\b/g

function mapFields(value: unknown, replacer: (value: string) => string): unknown {
  if (typeof value === 'string') return replacer(value)
  if (Array.isArray(value)) return value.map(item => mapFields(item, replacer))
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).flatMap(([name, field]) => {
      if (valueFields.has(name)) return []
      if (name === 'created_at' && typeof field === 'number') return [[name, 1_760_000_000]]
      return [[name, mapFields(field, replacer)]]
    }))
  }
  return value
}

export function comparableRequest(payload: unknown) {
  // Provider calls may include per-session cache keys and randomized message IDs.
  return mapFields(payload, value => value.replace(idPattern, (_value, prefix: string) => prefix + '_fixture'))
}

export function saveRecording(name: string, protocol: 'responses' | 'messages', calls: ProviderCall[], key: string) {
  const ids = new Map<string, string>()
  const replace = (input: string) => input.replace(idPattern, (value, prefix: string) => {
    let replacement = ids.get(value)
    if (!replacement) {
      replacement = prefix + '_fixture_' + String(ids.size + 1).padStart(4, '0')
      ids.set(value, replacement)
    }
    return replacement
  })
  const normalized = calls.map(call => ({
    ...call,
    request: mapFields(call.request, replace),
    body: call.body.split('\n').map(line => {
      if (!line.startsWith('data:') || line.includes('[DONE]') && line.trim() === 'data: [DONE]') return line
      return 'data: ' + JSON.stringify(mapFields(JSON.parse(line.slice(5)), replace))
    }).join('\n'),
  }))
  const contents = JSON.stringify({ provider: 'OpenRouter', model: DEFAULT_PROVIDER.model, protocol, scenario: name, calls: normalized }, null, 2) + '\n'
  if (contents.includes(key)) throw new Error('Refusing to save a fixture containing its credential.')
  mkdirSync('tests/fixtures', { recursive: true })
  writeFileSync(`tests/fixtures/openrouter-${protocol}-${name}.json`, contents)
  console.log(`Captured ${protocol} ${name} (${calls.length} HTTP requests).`)
}
