/**
 * v6 Phase 4 — fluid capability bundles, parallel read-only tools, and settlement retention.
 *
 * Covers plans/better-architecture.md §3.3:
 *   - additive bundles (base + browser/oob/race/http2/sast) attached by hypothesis shape;
 *   - no specialist loses the base HTTP/query/verify surface (no regex allowlist stripping);
 *   - pure read/query tools run concurrently in one round, network/mutation tools stay sequential;
 *   - settlement revokes network probes but keeps read/query/verify until the final turn.
 *
 * Fixtures are synthetic (no benchmark/app/route/seed literals, no external network).
 */
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { once } from 'node:events'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { randomUUID } from 'node:crypto'
import {
  SPECIALIST_COMMON_TOOLS,
  SPECIALIST_PROFILES,
  buildWorkerTools,
  capabilityBundlesFor,
  filterHandlersForSpecialist,
  investigatorTools,
  proofToolHandlerNames,
  runAgentSession,
  settlementToolBlock,
} from '../src/server/agent-session.ts'
import type { CapabilityBundle } from '../src/server/agent-session.ts'

const origin = 'https://app.example.invalid'
const dummy = async () => ({ ok: true })

function handlersFor(...names: string[]): Record<string, unknown> {
  return Object.fromEntries(names.map(name => [name, dummy]))
}

function filteredKeys(
  profileId: keyof typeof SPECIALIST_PROFILES,
  hypothesis: string,
  ...names: string[]
): string[] {
  return Object.keys(filterHandlersForSpecialist(
    handlersFor(...names) as never,
    SPECIALIST_PROFILES[profileId],
    hypothesis,
  ))
}

function tempDir(t: { after: (fn: () => void) => void }, prefix = 'kovo-v6-fluid-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

// ============================================================================
// 1. Additive capability bundles
// ============================================================================

test('base bundle always carries HTTP, graph/query, SAST/read, and verification tools', () => {
  const bundles = capabilityBundlesFor('')
  assert.deepEqual(bundles, ['http'])
  const base = investigatorTools(bundles)
  for (const name of ['request_http', 'request_http_batch', 'run_sast_scan', 'search_facts',
    'search_exchanges', 'get_exchange', 'expand_digest', 'kovo_verify', 'verify_replay_spec',
    'probe_differential', 'board_post', 'board_read']) {
    assert.ok(base.includes(name as never), `base bundle must include ${name}`)
  }
})

test('bundle classifier attaches capabilities additively from hypothesis shape', () => {
  const cases: Array<[string, CapabilityBundle[]]> = [
    ['Stored DOM sink reached through a checkout workflow replay', ['browser', 'race', 'http']],
    ['Blind SSRF and XXE callback through the XML parser', ['oob', 'http']],
    ['Concurrent TOCTOU double-spend burst', ['race', 'http']],
    ['HTTP/2 request smuggling and cache desync', ['http2', 'http']],
    ['Static source-to-sink suspect in the repo', ['sast', 'http']],
    ['Cross-tenant IDOR on /orders/{id}', ['http']],
  ]
  for (const [text, expected] of cases) {
    const bundles = capabilityBundlesFor(text)
    for (const bundle of expected) assert.ok(bundles.includes(bundle), `${text} must attach ${bundle}`)
  }
})

test('workflow investigator receives browser + verify + HTTP', () => {
  const keys = filteredKeys(
    'business-logic-race-specialist',
    'Stored DOM sink reached through a checkout workflow replay',
    'browser_visit', 'browser_session', 'kovo_verify', 'request_http', 'request_http_race',
    'search_facts',
  )
  assert.ok(keys.includes('browser_visit') && keys.includes('browser_session'))
  assert.ok(keys.includes('kovo_verify'))
  assert.ok(keys.includes('request_http') && keys.includes('request_http_race'))
  assert.ok(keys.includes('search_facts'), 'graph/query stays available')
})

test('injection investigator receives OOB + HTTP', () => {
  const keys = filteredKeys(
    'injection-parser-specialist',
    'Blind SSRF and XXE callback through the XML parser',
    'mint_canary', 'check_canary', 'mint_second_order_canary', 'kovo_verify', 'request_http',
  )
  for (const name of ['mint_canary', 'check_canary', 'mint_second_order_canary', 'kovo_verify', 'request_http']) {
    assert.ok(keys.includes(name), `injection bundle must include ${name}`)
  }
})

test('authz investigator receives HTTP + graph/query without browser escalation', () => {
  const keys = filteredKeys(
    'bola-bfla-specialist',
    'Cross-tenant IDOR on /orders/{id}',
    'request_http', 'request_http_batch', 'search_facts', 'get_exchange', 'expand_digest',
    'browser_visit', 'kovo_verify',
  )
  for (const name of ['request_http', 'request_http_batch', 'search_facts', 'get_exchange', 'expand_digest', 'kovo_verify']) {
    assert.ok(keys.includes(name), `authz investigator must keep ${name}`)
  }
  assert.ok(!keys.includes('browser_visit'), 'bundles are additive, not blanket: no browser without a client-side shape')
})

test('no specialist is missing kovo_verify when the handler exists', () => {
  for (const [id, profile] of Object.entries(SPECIALIST_PROFILES)) {
    const keys = Object.keys(filterHandlersForSpecialist(
      handlersFor('kovo_verify', 'request_http', 'search_facts', ...proofToolHandlerNames) as never,
      profile,
    ))
    assert.ok(keys.includes('kovo_verify'), `${id} must keep kovo_verify`)
    assert.ok(keys.includes('request_http'), `${id} must keep batched HTTP`)
    assert.ok(keys.includes('search_facts'), `${id} must keep graph/query search`)
    for (const proof of proofToolHandlerNames) {
      assert.ok(!keys.includes(proof), `${id} hides JSON proof compilers when kovo_verify exists`)
    }
  }
})

test('base bundle keeps board tools and drops nothing that was provided', () => {
  for (const tool of SPECIALIST_COMMON_TOOLS) {
    assert.ok(investigatorTools(capabilityBundlesFor('')).includes(tool), `${tool} must be in the base bundle`)
  }
})

// ============================================================================
// 2. Concurrency: read-only parallel, network/mutation sequential
// ============================================================================

test('tool registrations mark read-only tools parallel and network/mutation tools sequential', () => {
  const tools = buildWorkerTools(
    handlersFor('search_facts', 'get_exchange', 'request_http', 'record_fact') as never,
    value => value,
    AbortSignal.timeout(5_000),
    24 * 1024,
    () => {},
  )
  const mode = (name: string) => tools.find(tool => tool.name === name)?.executionMode
  assert.equal(mode('search_facts'), 'parallel')
  assert.equal(mode('get_exchange'), 'parallel')
  assert.equal(mode('request_http'), 'sequential')
  assert.equal(mode('record_fact'), 'sequential')
})

function ssePayload(response: { text?: string; toolCalls?: Array<{ name: string; args: unknown }> }): string {
  const events: unknown[] = []
  const output: unknown[] = []
  let idx = 0
  const responseId = 'resp_' + randomUUID().slice(0, 8)
  if (response.text !== undefined) {
    const msgId = 'msg_' + randomUUID().slice(0, 8)
    events.push({ type: 'response.output_item.added', output_index: idx, item: { id: msgId, type: 'message', status: 'in_progress', content: [] } })
    events.push({ type: 'response.output_item.done', output_index: idx, item: { id: msgId, type: 'message', status: 'completed', content: [{ type: 'output_text', text: response.text }] } })
    output.push({ id: msgId, type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: response.text }] })
    idx += 1
  }
  for (const call of response.toolCalls ?? []) {
    const fcId = 'fc_' + randomUUID().slice(0, 8)
    const callId = 'call_' + randomUUID().slice(0, 8)
    const serialized = JSON.stringify(call.args)
    events.push(
      { type: 'response.output_item.added', output_index: idx, item: { id: fcId, type: 'function_call', status: 'in_progress', call_id: callId, name: call.name, arguments: '' } },
      { type: 'response.function_call_arguments.delta', output_index: idx, item_id: fcId, delta: serialized },
      { type: 'response.function_call_arguments.done', output_index: idx, item_id: fcId, name: call.name, arguments: serialized },
      { type: 'response.output_item.done', output_index: idx, item: { id: fcId, type: 'function_call', status: 'completed', call_id: callId, name: call.name, arguments: serialized } },
    )
    output.push({ id: fcId, type: 'function_call', status: 'completed', call_id: callId, name: call.name, arguments: serialized })
    idx += 1
  }
  events.push({
    type: 'response.completed',
    response: { id: responseId, status: 'completed', output, usage: { input_tokens: 50, output_tokens: 20, total_tokens: 70 } },
  })
  return events.map(event => `data: ${JSON.stringify(event)}\n\n`).join('') + 'data: [DONE]\n\n'
}

async function fixtureServer(respond: () => { text?: string; toolCalls?: Array<{ name: string; args: unknown }> }) {
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    for await (const _chunk of req) { /* drain */ }
    res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(ssePayload(respond()))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('fixture has no address')
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>(resolve => server.close(() => resolve())),
  }
}

test('read-only calls in one round run concurrently', async (t) => {
  const dir = tempDir(t)
  let started = 0
  let release!: () => void
  const bothStarted = new Promise<void>(resolve => { release = resolve })
  const overlap = (name: string) => async () => {
    started += 1
    if (started === 2) release()
    await Promise.race([
      bothStarted,
      new Promise((_resolve, reject) => setTimeout(() => reject(new Error(`${name} did not overlap its peer`)), 1_500)),
    ])
    return { ok: true, name }
  }
  let calls = 0
  const server = await fixtureServer(() => calls++ === 0
    ? {
        toolCalls: [
          { name: 'search_facts', args: { query: 'order' } },
          { name: 'get_exchange', args: { exchangeId: 'ex-1' } },
        ],
      }
    : { text: 'concurrent-read-done' })
  t.after(() => server.close())

  const result = await runAgentSession({
    directory: dir,
    sessionId: 'concurrent-read',
    requestId: randomUUID(),
    settings: { endpoint: server.url, model: 'fixture-1', protocol: 'responses', key: 'fixture-key-1234' },
    scenario: 'worker-investigation',
    prompt: 'read evidence',
    signal: AbortSignal.timeout(20_000),
    maxTurns: 3,
    enableSettlement: false,
    requireCompleteIntent: false,
    handlers: { search_facts: overlap('search_facts'), get_exchange: overlap('get_exchange') } as never,
  })
  assert.equal(started, 2, 'both read-only handlers must start in the same round')
  assert.equal(result.answer, 'concurrent-read-done')
})

test('network calls stay sequential within one round', async (t) => {
  const dir = tempDir(t)
  let active = 0
  let maxActive = 0
  const network = async () => {
    active += 1
    maxActive = Math.max(maxActive, active)
    await new Promise(resolve => setTimeout(resolve, 40))
    active -= 1
    return { ok: true }
  }
  const httpArgs = { origin, method: 'GET', pathAndQuery: '/health' }
  let calls = 0
  const server = await fixtureServer(() => calls++ === 0
    ? { toolCalls: [{ name: 'request_http', args: httpArgs }, { name: 'request_http', args: httpArgs }] }
    : { text: 'sequential-network-done' })
  t.after(() => server.close())

  const result = await runAgentSession({
    directory: dir,
    sessionId: 'sequential-network',
    requestId: randomUUID(),
    settings: { endpoint: server.url, model: 'fixture-1', protocol: 'responses', key: 'fixture-key-1234' },
    scenario: 'worker-investigation',
    prompt: 'probe sequentially',
    signal: AbortSignal.timeout(20_000),
    maxTurns: 3,
    enableSettlement: false,
    requireCompleteIntent: false,
    handlers: { request_http: network } as never,
  })
  assert.equal(maxActive, 1, 'network tool calls must not overlap')
  assert.equal(result.answer, 'sequential-network-done')
})

// ============================================================================
// 3. Settlement: revoke probes, keep read/query/verify until the final turn
// ============================================================================

test('settlement revokes network probes but keeps queries and kovo_verify', () => {
  const atSettlement = { settling: true, turnsUsed: 20, maxTurns: 30 }
  for (const name of ['request_http', 'request_http_batch', 'request_http_race', 'browser_visit',
    'browser_session', 'probe_surface', 'probe_differential', 'run_safe_templates', 'probe_websocket']) {
    assert.ok(settlementToolBlock({ name, ...atSettlement }), `${name} must be revoked during settlement`)
  }
  for (const name of ['search_facts', 'search_exchanges', 'get_exchange', 'read_peer_trace',
    'expand_digest', 'board_read', 'query_cves', 'kovo_verify', 'verify_replay_spec']) {
    assert.equal(settlementToolBlock({ name, ...atSettlement }), undefined, `${name} must survive settlement`)
  }
  for (const name of ['record_fact', 'record_coverage', 'propose_chain_finding', 'complete_intent']) {
    assert.equal(settlementToolBlock({ name, ...atSettlement }), undefined, `${name} must stay available`)
  }
})

test('final turn also revokes read/query/verify wrap-up tools', () => {
  const finalTurn = { settling: true, turnsUsed: 30, maxTurns: 30 }
  for (const name of ['search_facts', 'expand_digest', 'kovo_verify']) {
    assert.match(settlementToolBlock({ name, ...finalTurn }) ?? '', /final turn/i)
  }
  assert.equal(settlementToolBlock({ name: 'record_fact', ...finalTurn }), undefined)
  assert.equal(settlementToolBlock({ name: 'request_http', settling: false, turnsUsed: 30, maxTurns: 30 }), undefined)
})
