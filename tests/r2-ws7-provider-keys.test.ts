/**
 * Regression suite for CLAUDE_AUDIT_R2 WS-7:
 *  - R2-H-2: Provider pool per-candidate API key isolation across round-robin, failover,
 *            mixed protocols (responses <-> messages <-> openrouter), and poisoned caller opts.
 *  - H-25:   Exact-only scrubbing on executable tool arguments (`run_offline_script.code`,
 *            `derive_evidence.command`, `kovo_verify.script`), separate `scrubForDisplay` vs
 *            `scrubExact`, `headers.Cookie` preservation in `llm_tool_args`, and exact-only
 *            Anthropic `signature` streaming channel.
 *  - H-8:    Live model-boundary secret scrubbing (dynamic getter AND mutated array) so secrets
 *            rotated/minted mid-run are immediately scrubbed from tool outputs, injected turn
 *            messages, outbound provider requests, and inbound provider streams.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import {
  buildWorkerTools,
  createSessionScrubbers,
  runAgentSession,
} from '../src/server/agent-session.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import { provider, providerPool } from '../src/server/provider.ts'
import { sanitizeProviderStream, sanitizeProviderValue } from '../src/server/provider-stream.ts'
import type { NamedSecret } from '../src/server/redact.ts'

function makeProfile(overrides: Partial<ResolvedModelProfile> & {
  id: string
  endpoint: string
  key: string
}): ResolvedModelProfile {
  return {
    name: overrides.id,
    model: 'test-model',
    protocol: 'responses',
    enabled: true,
    priority: 100,
    contextWindow: 128_000,
    maxTokens: 4096,
    inputCostPerMtok: 0.5,
    cachedInputCostPerMtok: 0.1,
    outputCostPerMtok: 1.5,
    thinkingLevel: 'off',
    roleAffinity: 'any',
    healthState: 'closed',
    cooldownUntil: null,
    lastError: null,
    ...overrides,
  }
}

function responsesSse(events: Array<{ type: string } & Record<string, unknown>>, done = true): string {
  return events.map(ev => `data: ${JSON.stringify(ev)}\n\n`).join('') + (done ? 'data: [DONE]\n\n' : '')
}

function messagesSse(events: Array<{ type: string } & Record<string, unknown>>): string {
  return events.map(ev => `event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`).join('')
}

function responsesTextTurn(text: string): string {
  const item = {
    type: 'message',
    id: 'msg_ws7',
    role: 'assistant',
    status: 'completed',
    content: [{ type: 'output_text', text, annotations: [] }],
  }
  return responsesSse([
    { type: 'response.created', response: { id: 'resp_ws7', status: 'in_progress' } },
    { type: 'response.output_item.added', output_index: 0, item: { ...item, content: [], status: 'in_progress' } },
    { type: 'response.output_text.delta', output_index: 0, content_index: 0, delta: text },
    { type: 'response.output_item.done', output_index: 0, item },
    {
      type: 'response.completed',
      response: {
        id: 'resp_ws7',
        status: 'completed',
        output: [item],
        usage: { input_tokens: 20, output_tokens: 10 },
      },
    },
  ])
}

function responsesToolCallTurn(callId: string, name: string, args: Record<string, unknown>): string {
  const argsJson = JSON.stringify(args)
  const item = {
    type: 'function_call',
    id: `fc_${callId}`,
    call_id: callId,
    name,
    arguments: argsJson,
    status: 'completed',
  }
  return responsesSse([
    { type: 'response.created', response: { id: `resp_${callId}`, status: 'in_progress' } },
    { type: 'response.output_item.added', output_index: 0, item: { ...item, arguments: '', status: 'in_progress' } },
    { type: 'response.function_call_arguments.delta', output_index: 0, delta: argsJson },
    { type: 'response.function_call_arguments.done', output_index: 0, arguments: argsJson },
    { type: 'response.output_item.done', output_index: 0, item },
    {
      type: 'response.completed',
      response: {
        id: `resp_${callId}`,
        status: 'completed',
        output: [item],
        usage: { input_tokens: 25, output_tokens: 15 },
      },
    },
  ])
}

function messagesTextTurn(text: string): string {
  return messagesSse([
    {
      type: 'message_start',
      message: {
        id: 'msg_anth_1',
        type: 'message',
        role: 'assistant',
        model: 'claude-test',
        content: [],
        stop_reason: null,
        stop_sequence: null,
        usage: { input_tokens: 15, output_tokens: 1 },
      },
    },
    { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
    { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text } },
    { type: 'content_block_stop', index: 0 },
    { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 8 } },
    { type: 'message_stop' },
  ])
}

function streamFromText(text: string, chunkSize = 17): ReadableStream<Uint8Array> {
  const buf = Buffer.from(text, 'utf8')
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (let off = 0; off < buf.length; off += chunkSize) {
        controller.enqueue(buf.subarray(off, off + chunkSize))
      }
      controller.close()
    },
  })
}

function parseSseData(sseText: string): Array<Record<string, unknown>> {
  return sseText
    .split('\n')
    .filter(line => line.startsWith('data: ') && line !== 'data: [DONE]')
    .map(line => JSON.parse(line.slice(6)) as Record<string, unknown>)
}

// ============================================================================
// 1. R2-H-2: Provider pool key isolation
// ============================================================================

describe('R2-H-2: Provider pool per-candidate API key isolation', () => {
  test('equal-priority round-robin sends each endpoint strictly its own key (never primary key)', async () => {
    const keyA = 'sk-profile-alpha-secret-111111'
    const keyB = 'sk-profile-bravo-secret-222222'
    const profileA = makeProfile({
      id: 'prof-a',
      endpoint: 'https://alpha.provider.test/v1',
      model: 'model-a',
      protocol: 'responses',
      key: keyA,
      priority: 100,
    })
    const profileB = makeProfile({
      id: 'prof-b',
      endpoint: 'https://bravo.provider.test/v1',
      model: 'model-b',
      protocol: 'responses',
      key: keyB,
      priority: 100,
    })

    const captured: Array<{ url: string; auth: string | null; xApiKey: string | null; apiKey: string | null }> = []
    const stubFetch: typeof fetch = async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      const h = new Headers(init?.headers)
      captured.push({
        url,
        auth: h.get('authorization'),
        xApiKey: h.get('x-api-key'),
        apiKey: h.get('api-key'),
      })
      const label = url.includes('alpha.provider.test') ? 'from-alpha' : 'from-bravo'
      return new Response(responsesTextTurn(label), {
        status: 200,
        headers: { 'content-type': 'text/event-stream' },
      })
    }

    const { models, model } = providerPool([profileA, profileB], 'coordinator', { fetch: stubFetch })
    const transcript = {
      systemPrompt: 'Say hi.',
      messages: [{ role: 'user' as const, content: 'ping', timestamp: Date.now() }],
      tools: [],
    }

    for (let i = 0; i < 4; i++) {
      const s = models.stream(model, transcript)
      for await (const _ev of s) { /* drain */ }
      const res = await s.result()
      assert.notEqual(res.stopReason, 'error', res.errorMessage ?? 'unexpected error')
    }

    assert.equal(captured.length, 4)
    const alphaHits = captured.filter(c => c.url.includes('alpha.provider.test'))
    const bravoHits = captured.filter(c => c.url.includes('bravo.provider.test'))
    assert.ok(alphaHits.length >= 1, 'alpha endpoint must be exercised by round-robin')
    assert.ok(bravoHits.length >= 1, 'bravo endpoint must be exercised by round-robin')

    for (const hit of alphaHits) {
      assert.equal(hit.auth, `Bearer ${keyA}`)
      assert.equal(hit.xApiKey, null)
      assert.equal(hit.apiKey, null)
    }
    for (const hit of bravoHits) {
      assert.equal(hit.auth, `Bearer ${keyB}`)
      assert.equal(hit.xApiKey, null)
      assert.equal(hit.apiKey, null)
      assert.ok(!hit.auth?.includes(keyA), 'primary key A must NEVER be sent to endpoint B')
    }
  })

  test('failover across mixed protocols (responses -> messages) and OpenRouter strips/resets auth headers per candidate', async () => {
    const primaryKey = 'sk-primary-openai-key-aaaaaaa'
    const anthropicBackupKey = 'sk-ant-backup-key-bbbbbbbbbb'
    const openRouterKey = 'sk-or-v1-tertiary-ccccccccccc'

    const pPrimary = makeProfile({
      id: 'p-primary',
      endpoint: 'https://primary-openai.test/v1',
      model: 'gpt-primary',
      protocol: 'responses',
      key: primaryKey,
      priority: 300,
    })
    const pAnthropic = makeProfile({
      id: 'p-anthropic',
      endpoint: 'https://backup-anthropic.test/v1',
      model: 'claude-backup',
      protocol: 'messages',
      key: anthropicBackupKey,
      priority: 200,
    })
    const pOpenRouter = makeProfile({
      id: 'p-openrouter',
      endpoint: 'https://openrouter.ai/api/v1',
      model: 'anthropic/claude-or',
      protocol: 'messages',
      key: openRouterKey,
      priority: 100,
    })

    const calls: Array<{ url: string; auth: string | null; xApiKey: string | null; apiKey: string | null }> = []
    let failAnthropic = false

    const stubFetch: typeof fetch = async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      const h = new Headers(init?.headers)
      calls.push({
        url,
        auth: h.get('authorization'),
        xApiKey: h.get('x-api-key'),
        apiKey: h.get('api-key'),
      })
      if (url.includes('primary-openai.test')) {
        return new Response(JSON.stringify({ error: { message: 'insufficient quota' } }), {
          status: 402,
          headers: { 'content-type': 'application/json' },
        })
      }
      if (url.includes('backup-anthropic.test')) {
        if (failAnthropic) {
          return new Response(JSON.stringify({ error: { message: 'unauthorized' } }), {
            status: 401,
            headers: { 'content-type': 'application/json' },
          })
        }
        // Echo primaryKey in response text to also verify pool redacts ALL pool keys
        return new Response(messagesTextTurn(`backup-ok-leak:${primaryKey}`), {
          status: 200,
          headers: { 'content-type': 'text/event-stream' },
        })
      }
      return new Response(messagesTextTurn('openrouter-ok'), {
        status: 200,
        headers: { 'content-type': 'text/event-stream' },
      })
    }

    const { models, model } = providerPool([pPrimary, pAnthropic, pOpenRouter], 'coordinator', {
      fetch: stubFetch,
    })
    const transcript = {
      systemPrompt: 'Test failover.',
      messages: [{ role: 'user' as const, content: 'go', timestamp: Date.now() }],
      tools: [],
    }

    // Pass a poisoned caller `apiKey` in sOpts to confirm streamOpts + wrapMethod + makeFetch override it.
    const s1 = models.stream(model, transcript, { apiKey: 'sk-poisoned-caller-key-999999' })
    for await (const _ev of s1) { /* drain */ }
    const r1 = await s1.result()
    assert.notEqual(r1.stopReason, 'error', r1.errorMessage ?? 'unexpected error')

    assert.equal(calls.length, 2)
    assert.equal(calls[0]!.url, 'https://primary-openai.test/v1/responses')
    assert.equal(calls[0]!.auth, `Bearer ${primaryKey}`)
    assert.equal(calls[0]!.xApiKey, null)
    assert.equal(calls[0]!.apiKey, null)

    assert.ok(calls[1]!.url.startsWith('https://backup-anthropic.test/v1/messages'))
    assert.equal(calls[1]!.xApiKey, anthropicBackupKey)
    assert.equal(calls[1]!.auth, null, 'Anthropic endpoint must NOT receive primary Bearer header')
    assert.equal(calls[1]!.apiKey, null)

    const r1Text = r1.content.filter(p => p.type === 'text').map(p => p.text).join('')
    assert.ok(!r1Text.includes(primaryKey), 'pool must redact primary key even when echoed by backup profile')
    assert.ok(r1Text.includes('[redacted]'))

    // Now also fail Anthropic -> failover to OpenRouter (messages protocol over openrouter.ai uses Bearer, not x-api-key)
    failAnthropic = true
    calls.length = 0
    const s2 = models.streamSimple(model, transcript, { apiKey: primaryKey })
    for await (const _ev of s2) { /* drain */ }
    const r2 = await s2.result()
    assert.notEqual(r2.stopReason, 'error', r2.errorMessage ?? 'unexpected error')

    assert.equal(calls.length, 3)
    assert.ok(calls[2]!.url.startsWith('https://openrouter.ai/api/v1/messages'))
    assert.equal(calls[2]!.auth, `Bearer ${openRouterKey}`)
    assert.equal(calls[2]!.xApiKey, null)
    assert.equal(calls[2]!.apiKey, null)
  })

  test('single provider() strips caller-injected apiKey / x-api-key / api-key headers in makeFetch', async () => {
    const expectedKey = 'sk-single-expected-key-55555'
    let seenHeaders: Headers | undefined
    const { models, model } = provider(
      {
        endpoint: 'https://single.provider.test/v1',
        model: 'single-model',
        protocol: 'responses',
        key: expectedKey,
      },
      'coordinator',
      {
        fetch: async (_input, init) => {
          seenHeaders = new Headers(init?.headers)
          return new Response(responsesTextTurn('single-ok'), {
            status: 200,
            headers: { 'content-type': 'text/event-stream' },
          })
        },
      },
    )
    const s = models.stream(model, {
      systemPrompt: 'Test.',
      messages: [{ role: 'user', content: 'hi', timestamp: Date.now() }],
      tools: [],
    }, {
      apiKey: 'sk-wrong-override-key-99999',
      headers: { 'x-api-key': 'sk-leaked-x-api-key', 'api-key': 'sk-leaked-api-key' },
    })
    for await (const _ev of s) { /* drain */ }
    const res = await s.result()
    assert.notEqual(res.stopReason, 'error', res.errorMessage ?? 'unexpected error')
    assert.ok(seenHeaders)
    assert.equal(seenHeaders!.get('authorization'), `Bearer ${expectedKey}`)
    assert.equal(seenHeaders!.get('x-api-key'), null)
    assert.equal(seenHeaders!.get('api-key'), null)
  })
})

// ============================================================================
// 2. H-25: Exact-only executable args, scrubForDisplay vs scrubExact, headers.Cookie
// ============================================================================

describe('H-25: Non-destructive executable tool arguments and llm_tool_args Cookie handling', () => {
  test('run_offline_script, derive_evidence, and kovo_verify keep code/command byte-identical except exact secrets', async () => {
    const vaultSecret = 'vault-exec-secret-token-774411'
    const providerKey = 'sk-provider-exec-key-998877'
    const scrubbers = createSessionScrubbers(
      [{ value: vaultSecret, placeholder: '[persona:tenant_a:secret]' }],
      [{ value: providerKey, placeholder: '[redacted]' }],
    )

    let receivedCode = ''
    let receivedCommand = ''
    let receivedVerifyScript = ''

    const tools = buildWorkerTools(
      {
        run_offline_script: async args => {
          receivedCode = args.code
          return { stdout: `output password=display-only-pw secret=${vaultSecret}` }
        },
        derive_evidence: async args => {
          receivedCommand = args.command
          return { stdout: `found Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0. ${vaultSecret}` }
        },
        kovo_verify: async args => {
          receivedVerifyScript = args.script ?? ''
          return { verdict: 'inconclusive', transcriptSummary: [] }
        },
      },
      scrubbers,
      AbortSignal.timeout(5_000),
      64 * 1024,
      () => undefined,
    )

    const byName = (name: string) => {
      const tool = tools.find(t => t.name === name)
      assert.ok(tool, `expected tool ${name}`)
      return tool
    }

    const sampleJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.sig_part_1234'
    const offlineCode = [
      "import jwt",
      `token = "${sampleJwt}"`,
      "password = 'probe-password-123'",
      "secret_key = 'probe-signing-key'",
      "headers = {'Authorization': 'Bearer probe-bearer-token-999', 'Cookie': 'role=probe'}",
      `leaked = "${vaultSecret}"`,
    ].join('\n')

    const offlineOut = await byName('run_offline_script').execute(
      { runtime: 'python', code: offlineCode } as never,
      {} as never,
      { abortSignal: AbortSignal.timeout(5_000) } as never,
    )
    assert.equal(receivedCode, offlineCode.replace(vaultSecret, '[persona:tenant_a:secret]'))
    assert.ok(receivedCode.includes(sampleJwt), 'JWT literal in Python code must not be heuristically redacted')
    assert.ok(receivedCode.includes("password = 'probe-password-123'"))
    assert.ok(receivedCode.includes("secret_key = 'probe-signing-key'"))
    assert.ok(receivedCode.includes("'Cookie': 'role=probe'"))
    assert.ok(!receivedCode.includes(vaultSecret))

    // Display output of the tool MUST still apply heuristic + exact scrubbing via scrubForDisplay
    const offlineText = (offlineOut.output ?? []).map(o => ('text' in o ? o.text : '')).join('')
    assert.ok(!offlineText.includes('display-only-pw'), 'scrubForDisplay must still scrub heuristic password in tool output')
    assert.ok(!offlineText.includes(vaultSecret), 'scrubForDisplay must scrub exact secret in tool output')

    const deriveCmd = `rg -n "password=|secret_key=|token=|Cookie:" /repos/app && echo "${sampleJwt}" # ${vaultSecret}`
    const deriveOut = await byName('derive_evidence').execute(
      { command: deriveCmd } as never,
      {} as never,
      { abortSignal: AbortSignal.timeout(5_000) } as never,
    )
    assert.equal(receivedCommand, deriveCmd.replace(vaultSecret, '[persona:tenant_a:secret]'))
    assert.ok(receivedCommand.includes('password=|secret_key=|token=|Cookie:'))
    assert.ok(receivedCommand.includes(sampleJwt))
    assert.ok(!receivedCommand.includes(vaultSecret))

    const deriveText = (deriveOut.output ?? []).map(o => ('text' in o ? o.text : '')).join('')
    assert.ok(!deriveText.includes(vaultSecret))
    assert.ok(!deriveText.includes('eyJhbGciOiJub25lIn0'), 'scrubForDisplay must scrub heuristic JWT in tool output')

    const verifyCode = [
      "const res = await ctx.http({ method: 'GET', path: '/api/me', headers: { Cookie: 'role=probe', Authorization: 'Bearer probe-tok-123456' } })",
      `const expected = "${sampleJwt}"`,
      `const bad = "${vaultSecret}"`,
      "return ctx.result({ title: 'check' })",
    ].join('\n')
    await byName('kovo_verify').execute(
      { script: verifyCode, runtime: 'ts' } as never,
      {} as never,
      { abortSignal: AbortSignal.timeout(5_000) } as never,
    )
    assert.equal(receivedVerifyScript, verifyCode.replace(vaultSecret, '[persona:tenant_a:secret]'))
    assert.ok(receivedVerifyScript.includes("Cookie: 'role=probe'"))
    assert.ok(receivedVerifyScript.includes(sampleJwt))
    assert.ok(!receivedVerifyScript.includes(vaultSecret))
  })

  test('provider-stream preserves headers.Cookie in llm_tool_args and exact-only thinking signatures', async () => {
    const providerKey = 'sk-stream-h25-key-445566'
    const vaultSecret = 'vault-cookie-secret-889900'
    const secrets: NamedSecret[] = [{ value: vaultSecret, placeholder: '[persona:user_a:secret]' }]

    const toolArgs = {
      origin: 'https://target.example',
      method: 'GET',
      pathAndQuery: '/api/profile',
      headers: {
        Cookie: 'role=probe; theme=dark',
        Authorization: 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.',
      },
      reqHeaders: {
        cookie: `sid=${vaultSecret}; prefs=1`,
      },
    }
    const argsJson = JSON.stringify(toolArgs)
    const mid = Math.floor(argsJson.length / 2)

    const respWire = responsesSse([
      { type: 'response.output_item.added', output_index: 0, item: { type: 'function_call', call_id: 'c1', name: 'request_http', arguments: '' } },
      { type: 'response.function_call_arguments.delta', output_index: 0, delta: argsJson.slice(0, mid) },
      { type: 'response.function_call_arguments.delta', output_index: 0, delta: argsJson.slice(mid) },
      { type: 'response.function_call_arguments.done', output_index: 0, arguments: argsJson },
      { type: 'response.completed', response: { status: 'completed', output: [{ type: 'function_call', call_id: 'c1', name: 'request_http', arguments: argsJson }] } },
    ])

    const safeResp = await new Response(
      sanitizeProviderStream(streamFromText(respWire), providerKey, 'responses', { secrets }),
    ).text()
    const respEvents = parseSseData(safeResp)
    const joinedArgs = (respEvents[1]!.delta as string) + (respEvents[2]!.delta as string)
    const parsedArgs = JSON.parse(joinedArgs) as typeof toolArgs

    assert.equal(parsedArgs.headers.Cookie, 'role=probe; theme=dark', 'headers.Cookie must NOT be clobbered in llm_tool_args')
    assert.equal(parsedArgs.headers.Authorization, toolArgs.headers.Authorization)
    assert.equal(parsedArgs.reqHeaders.cookie, 'sid=[persona:user_a:secret]; prefs=1', 'exact vault secret inside headers.cookie must still be redacted')
    assert.ok(!safeResp.includes(vaultSecret))
    assert.deepEqual(JSON.parse(respEvents[3]!.arguments as string), parsedArgs)

    // Messages protocol: tool_use input preserves headers.Cookie, AND signature_delta is exact-only
    const signatureToken = 'eyJhbGciOiJSUzI1NiJ9.eyJ0aGlua2luZyI6dHJ1ZX0.signature_payload_998877'
    const msgWire = messagesSse([
      {
        type: 'content_block_start',
        index: 0,
        content_block: { type: 'thinking', thinking: '', signature: '' },
      },
      {
        type: 'content_block_delta',
        index: 0,
        delta: { type: 'signature_delta', signature: signatureToken.slice(0, 24) },
      },
      {
        type: 'content_block_delta',
        index: 0,
        delta: { type: 'signature_delta', signature: signatureToken.slice(24) },
      },
      {
        type: 'content_block_start',
        index: 1,
        content_block: {
          type: 'tool_use',
          id: 'toolu_cookie',
          name: 'request_http',
          input: { headers: { Cookie: 'session=probe_cookie_val', 'X-Note': vaultSecret } },
        },
      },
      { type: 'message_stop' },
    ])

    const safeMsg = await new Response(
      sanitizeProviderStream(streamFromText(msgWire), providerKey, 'messages', { secrets }),
    ).text()
    const msgEvents = parseSseData(safeMsg)
    const joinedSig = ((msgEvents[1]!.delta as { signature: string }).signature) +
      ((msgEvents[2]!.delta as { signature: string }).signature)
    assert.equal(joinedSig, signatureToken, 'thinking signature channel must be exact-only (never corrupted by heuristic JWT regex)')

    const toolUseInput = (msgEvents[3]!.content_block as { input: { headers: Record<string, string> } }).input
    assert.equal(toolUseInput.headers.Cookie, 'session=probe_cookie_val')
    assert.equal(toolUseInput.headers['X-Note'], '[persona:user_a:secret]')

    // Non-delta sanitizeProviderValue on thinking block preserves signature too
    const sanitizedThinking = sanitizeProviderValue(
      { type: 'thinking', thinking: 'password=should-redact-prose', signature: signatureToken },
      providerKey,
      undefined,
      secrets,
    ) as { thinking: string; signature: string }
    assert.equal(sanitizedThinking.signature, signatureToken)
    assert.ok(!sanitizedThinking.thinking.includes('should-redact-prose'))
  })
})

// ============================================================================
// 3. H-8: Live model-boundary secret scrubbing after mid-run token rotation
// ============================================================================

describe('H-8: Live model-boundary secret scrubbing picks up secrets rotated mid-run', () => {
  test('createSessionScrubbers reads live getter and mutated array without startup snapshot', () => {
    const initialSecret = 'initial-session-tok-11111'
    const rotatedSecret = 'rotated-session-tok-99999'

    // 1. Dynamic getter
    const liveStore: NamedSecret[] = [{ value: initialSecret, placeholder: '[persona:p1:init]' }]
    const getterScrub = createSessionScrubbers(() => liveStore)
    assert.equal(getterScrub.scrubForDisplay(`tok=${initialSecret}`), 'tok=[persona:p1:init]')
    assert.equal(getterScrub.scrubExact(`raw:${rotatedSecret}`), `raw:${rotatedSecret}`)

    // Rotate mid-run
    liveStore.push({ value: rotatedSecret, placeholder: '[persona:p1:rotated]' })
    assert.equal(getterScrub.scrubForDisplay(`val=${rotatedSecret}`), 'val=[persona:p1:rotated]')
    assert.equal(getterScrub.scrubExact(`code="${rotatedSecret}"`), 'code="[persona:p1:rotated]"')
    const b64Rotated = Buffer.from(rotatedSecret).toString('base64')
    assert.equal(getterScrub.scrubExact(`b64=${b64Rotated}`), 'b64=[persona:p1:rotated]')

    // 2. Mutable array passed directly (not copied at startup)
    const mutableArr: NamedSecret[] = [{ value: initialSecret, placeholder: '[persona:p2:init]' }]
    const arrayScrub = createSessionScrubbers(mutableArr)
    mutableArr.push({ value: rotatedSecret, placeholder: '[persona:p2:rotated]' })
    assert.equal(arrayScrub.scrubForDisplay(`leaked ${rotatedSecret}`), 'leaked [persona:p2:rotated]')
    assert.equal(arrayScrub.scrubExact(`leaked ${rotatedSecret}`), 'leaked [persona:p2:rotated]')
  })

  test('runAgentSession scrubs secrets rotated mid-run across tool outputs, turn injections, outbound requests, and inbound streams', async t => {
    const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
    process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
    t.after(() => {
      if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
      else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
    })

    const dir = mkdtempSync(join(tmpdir(), 'kovo-ws7-h8-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))

    const initialSecret = 'init-persona-secret-abc123'
    const rotatedSecret = 'rotated-midrun-secret-xyz987654'
    const rotatedB64 = Buffer.from(rotatedSecret).toString('base64')
    const liveSecrets: NamedSecret[] = [
      { value: initialSecret, placeholder: '[persona:actor:init]' },
    ]

    const receivedRequestBodies: string[] = []
    let turnCount = 0

    const server = createServer((req, res) => {
      const chunks: Buffer[] = []
      req.on('data', c => chunks.push(Buffer.from(c)))
      req.on('end', () => {
        receivedRequestBodies.push(Buffer.concat(chunks).toString('utf8'))
        turnCount += 1
        res.writeHead(200, { 'content-type': 'text/event-stream' })
        if (turnCount === 1) {
          res.end(responsesToolCallTurn('call_rot_1', 'derive_evidence', {
            command: 'rg -n "token=" /evidence/sample.txt',
          }))
          return
        }
        // Turn 2: model attempts to echo the rotated secret in its final answer
        res.end(responsesTextTurn(`Completed analysis with ${rotatedSecret} and ${rotatedB64}.`))
      })
    }).listen(0, '127.0.0.1')
    await once(server, 'listening')
    t.after(async () => {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    })
    const port = (server.address() as AddressInfo).port

    let observedCmd = ''
    const result = await runAgentSession({
      directory: dir,
      sessionId: 'ws7-live-scrub-session',
      requestId: 'ws7-live-scrub-req',
      settings: {
        endpoint: `http://127.0.0.1:${port}/v1`,
        model: 'mock-h8',
        protocol: 'responses',
        key: 'sk-h8-local-fixture-key-1234',
      },
      scenario: 'worker-investigation',
      prompt: `Investigate target using ${initialSecret}.`,
      signal: AbortSignal.timeout(10_000),
      maxTurns: 4,
      compaction: false,
      enableSettlement: false,
      requireCompleteIntent: false,
      secrets: () => liveSecrets,
      handlers: {
        derive_evidence: async ({ command }) => {
          observedCmd = command
          // Simulate mid-run session rotation minting a brand new secret!
          liveSecrets.push({ value: rotatedSecret, placeholder: '[persona:actor:rotated]' })
          return { stdout: `rotated=${rotatedSecret} b64=${rotatedB64}` }
        },
      },
      onTurnStart: turn => {
        if (turn === 2) {
          return { messages: [`<board_delta>peer saw ${rotatedSecret}</board_delta>`] }
        }
        return undefined
      },
    })

    // H-25 check inside live runAgentSession: derive_evidence command was NOT heuristically mangled
    assert.equal(observedCmd, 'rg -n "token=" /evidence/sample.txt')

    // H-8 checks:
    assert.equal(receivedRequestBodies.length, 2)
    // Turn 1 request scrubbed initialSecret
    assert.ok(!receivedRequestBodies[0]!.includes(initialSecret), 'Turn 1 request must not leak initial secret')
    assert.ok(receivedRequestBodies[0]!.includes('[persona:actor:init]'))

    // Turn 2 request scrubbed rotatedSecret from BOTH tool output AND onTurnStart board_delta!
    assert.ok(!receivedRequestBodies[1]!.includes(rotatedSecret), 'Turn 2 outbound request must NOT contain mid-run rotated secret')
    assert.ok(!receivedRequestBodies[1]!.includes(rotatedB64), 'Turn 2 outbound request must NOT contain base64 of mid-run rotated secret')
    assert.ok(receivedRequestBodies[1]!.includes('[persona:actor:rotated]'))

    // Inbound response stream scrubbed rotatedSecret live before returning session.answer!
    assert.ok(!result.answer.includes(rotatedSecret), 'session.answer must NOT contain mid-run rotated secret')
    assert.ok(!result.answer.includes(rotatedB64), 'session.answer must NOT contain base64 of mid-run rotated secret')
    assert.ok(result.answer.includes('[persona:actor:rotated]'))
  })

  test('provider() live secrets getter scrubs late secrets in outbound request body and inbound SSE stream', async () => {
    const liveSecrets: NamedSecret[] = []
    const lateSecret = 'late-minted-provider-secret-554433'
    let capturedOutbound = ''

    const { models, model } = provider(
      {
        endpoint: 'https://live-scrub.provider.test/v1',
        model: 'mock-live',
        protocol: 'responses',
        key: 'sk-live-provider-key-112233',
      },
      'coordinator',
      {
        secrets: () => liveSecrets,
        fetch: async (_input, init) => {
          capturedOutbound = String(init?.body ?? '')
          return new Response(responsesTextTurn(`echo:${lateSecret}`), {
            status: 200,
            headers: { 'content-type': 'text/event-stream' },
          })
        },
      },
    )

    // Mint secret AFTER provider() has already been constructed
    liveSecrets.push({ value: lateSecret, placeholder: '[persona:late:secret]' })

    const s = models.stream(model, {
      systemPrompt: 'Summarize.',
      messages: [{ role: 'user', content: `context containing ${lateSecret}`, timestamp: Date.now() }],
      tools: [],
    })
    for await (const _ev of s) { /* drain */ }
    const res = await s.result()

    assert.ok(!capturedOutbound.includes(lateSecret), 'outbound provider request must scrub secret registered after provider() init')
    assert.ok(capturedOutbound.includes('[persona:late:secret]'))
    const text = res.content.filter(p => p.type === 'text').map(p => p.text).join('')
    assert.ok(!text.includes(lateSecret), 'inbound provider stream must scrub secret registered after provider() init')
    assert.ok(text.includes('[persona:late:secret]'))
  })
})
