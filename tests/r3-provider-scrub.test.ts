// @kernel @fixes R3-H-10
/**
 * Regression suite for CLAUDE_AUDIT_R3 R3-H-10:
 *  1. Outbound provider request scrubbing walks ONLY content-bearing leaves (`instructions`,
 *     `system`, message `content`/`text`, tool call `arguments`/`input`, tool `output`/`tool_result`)
 *     and NEVER mutates object keys or protocol/structural metadata (`role`, `type`, `tool_choice`,
 *     `reasoning.summary`, `reasoning.effort`, `model`, tool definitions/JSON schemas, `status`,
 *     `call_id`, `id`, `signature`).
 *  2. Persona secret needle extraction raises the minimum floor to >= 8 chars with entropy /
 *     dictionary checks and restricts cookie-derived needles to auth/session-relevant cookie names
 *     (or high-entropy tokens >= 16 chars / JWTs), while keeping genuine credentials 100% redacted.
 *  3. Null-prototype & reserved-key safety (`__proto__`, `constructor`, `toString`, `hasOwnProperty`).
 *  4. Local request integrity verification and clear diagnostic reporting on local-mutation HTTP 400s.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import { obj, str, union, lit } from '@earendil-works/pi-schema'
import {
  bundleSecrets,
  extractBrowserBundleSecrets,
  isAcceptableSecretNeedle,
  isAuthRelevantCookieName,
  isScrubbableCookieNeedle,
  normalizeBrowserStorageBundle,
  personaSecrets,
  writePersonaSessionFile,
  type MintedPersonaSession,
  type PersonaCredentialBundle,
  type ResolvedPersona,
} from '../src/server/persona-vault.ts'
import {
  classifyProviderFailure,
  provider,
} from '../src/server/provider.ts'
import {
  scrubExactSecretsValue,
  scrubOutboundProviderRequest,
  verifyOutboundProviderRequestIntegrity,
} from '../src/server/provider-stream.ts'
import type { NamedSecret } from '../src/server/redact.ts'

function responsesTextTurn(text: string): string {
  const item = {
    type: 'message',
    id: 'msg_r3_h10',
    role: 'assistant',
    status: 'completed',
    content: [{ type: 'output_text', text, annotations: [] }],
  }
  return [
    { type: 'response.created', response: { id: 'resp_r3_h10', status: 'in_progress' } },
    { type: 'response.output_item.added', output_index: 0, item: { ...item, content: [], status: 'in_progress' } },
    { type: 'response.output_text.delta', output_index: 0, content_index: 0, delta: text },
    { type: 'response.output_item.done', output_index: 0, item },
    {
      type: 'response.completed',
      response: {
        id: 'resp_r3_h10',
        status: 'completed',
        output: [item],
        usage: { input_tokens: 18, output_tokens: 8 },
      },
    },
  ].map(ev => `data: ${JSON.stringify(ev)}\n\n`).join('') + 'data: [DONE]\n\n'
}

function messagesTextTurn(text: string): string {
  return [
    {
      type: 'message_start',
      message: {
        id: 'msg_r3_anth',
        type: 'message',
        role: 'assistant',
        model: 'claude-r3-test',
        content: [],
        stop_reason: null,
        stop_sequence: null,
        usage: { input_tokens: 15, output_tokens: 1 },
      },
    },
    { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
    { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text } },
    { type: 'content_block_stop', index: 0 },
    { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 6 } },
    { type: 'message_stop' },
  ].map(ev => `event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`).join('')
}

// ============================================================================
// 1. Persona secret needle quality (persona-vault.ts)
// ============================================================================

describe('R3-H-10: Persona secret needle quality & cookie classification', () => {
  test('short protocol words and generic preference cookies never enter exact-scrub needles', () => {
    const protocolWordCookies = [
      { name: 'role', value: 'user' },
      { name: 'mode', value: 'auto' },
      { name: 'format', value: 'text' },
      { name: 'scope', value: 'system' },
      { name: 'input_kind', value: 'input_text' },
      { name: 'summary', value: 'concise' },
      { name: 'flag', value: 'true' },
      { name: 'opt', value: 'none' },
      { name: 'theme', value: 'dark' },
      { name: 'locale', value: 'en_US' },
      { name: 'prefs', value: 'dark_mode_enabled' },
      { name: 'session_id', value: 'user' },
      { name: 'auth_token', value: 'concise' },
      { name: 'sid', value: 'input_text' },
      { name: 'csrf_token', value: 'aaaaaaaa' },
    ]

    for (const c of protocolWordCookies) {
      assert.equal(
        isScrubbableCookieNeedle(c.name, c.value),
        false,
        `cookie ${c.name}=${c.value} must NOT enter exact-scrub needle set`,
      )
    }

    assert.equal(isAuthRelevantCookieName('role'), false)
    assert.equal(isAuthRelevantCookieName('theme'), false)
    assert.equal(isAuthRelevantCookieName('locale'), false)
    assert.equal(isAuthRelevantCookieName('prefs'), false)
    assert.equal(isAuthRelevantCookieName('sid'), true)
    assert.equal(isAuthRelevantCookieName('__session'), true)
    assert.equal(isAuthRelevantCookieName('XSRF-TOKEN'), true)
    assert.equal(isAuthRelevantCookieName('next-auth.session-token'), true)
    assert.equal(isAuthRelevantCookieName('__Host-csrf_token'), true)

    assert.equal(isAcceptableSecretNeedle('user'), false)
    assert.equal(isAcceptableSecretNeedle('auto'), false)
    assert.equal(isAcceptableSecretNeedle('text'), false)
    assert.equal(isAcceptableSecretNeedle('true'), false)
    assert.equal(isAcceptableSecretNeedle('none'), false)
    assert.equal(isAcceptableSecretNeedle('concise'), false)
    assert.equal(isAcceptableSecretNeedle('input_text'), false)
    assert.equal(isAcceptableSecretNeedle('browser_session'), false)
    assert.equal(isAcceptableSecretNeedle('aaaaaaaaaaaa'), false)
  })

  test('bundleSecrets, extractBrowserBundleSecrets, writePersonaSessionFile, and personaSecrets keep genuine credentials while rejecting benign cookies', t => {
    const genuineSessionCookie = 'sess_live_9f8e7d6c5b4a3210fedcba'
    const genuineCsrfToken = 'csrf_tok_88a7b6c5d4e3f2'
    const genuineShortAuthSid = 'sid98765432'
    const genuineHighEntropyGeneric = 'k9M2pQ7vX4nL8wR1z8T3'
    const genuineJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyJ9.sig_abc123def456'
    const genuineApiKey = 'sk_live_r3h10_secret_key_99887766'

    const bundle: PersonaCredentialBundle = {
      cookies: [
        { name: 'role', value: 'user', domain: 'app.test', path: '/' },
        { name: 'mode', value: 'auto', domain: 'app.test', path: '/' },
        { name: 'format', value: 'text', domain: 'app.test', path: '/' },
        { name: 'summary', value: 'concise', domain: 'app.test', path: '/' },
        { name: 'kind', value: 'input_text', domain: 'app.test', path: '/' },
        { name: 'theme', value: 'dark_mode_enabled', domain: 'app.test', path: '/' },
        { name: 'app_session', value: genuineSessionCookie, domain: 'app.test', path: '/', httpOnly: true },
        { name: 'XSRF-TOKEN', value: genuineCsrfToken, domain: 'app.test', path: '/' },
        { name: 'sid', value: genuineShortAuthSid, domain: 'app.test', path: '/' },
        { name: 'x_opaque_state', value: genuineHighEntropyGeneric, domain: 'app.test', path: '/' },
      ],
      headers: {
        Authorization: `Bearer ${genuineJwt}`,
        'X-Api-Key': genuineApiKey,
        Cookie: 'role=user; mode=auto; summary=concise',
      },
      storage: {
        localStorage: {
          theme: 'dark',
          auth_token: genuineJwt,
          short_token: 'auto',
        },
      },
    }

    const fromBundle = bundleSecrets(bundle)
    for (const benign of ['user', 'auto', 'text', 'concise', 'input_text', 'dark', 'dark_mode_enabled', 'role=user; mode=auto; summary=concise']) {
      assert.ok(!fromBundle.includes(benign), `bundleSecrets must exclude benign value "${benign}"`)
    }
    for (const genuine of [genuineSessionCookie, genuineCsrfToken, genuineShortAuthSid, genuineHighEntropyGeneric, genuineJwt, genuineApiKey]) {
      assert.ok(fromBundle.includes(genuine), `bundleSecrets must retain genuine secret "${genuine}"`)
    }

    const browserBundle = normalizeBrowserStorageBundle({
      v: 1,
      kind: 'browser_session',
      targetOrigin: 'https://app.test',
      capturedAt: Date.now(),
      storageState: {
        cookies: [
          { name: 'role', value: 'user', domain: 'app.test', path: '/', expires: -1, httpOnly: false, secure: true, sameSite: 'Lax' },
          { name: 'mode', value: 'auto', domain: 'app.test', path: '/', expires: -1, httpOnly: false, secure: true, sameSite: 'Lax' },
          { name: 'summary', value: 'concise', domain: 'app.test', path: '/', expires: -1, httpOnly: false, secure: true, sameSite: 'Lax' },
          { name: '__session', value: genuineSessionCookie, domain: 'app.test', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'Lax' },
        ],
        origins: [{
          origin: 'https://app.test',
          localStorage: [
            { name: 'ui_mode', value: 'concise' },
            { name: 'access_token', value: genuineJwt },
          ],
        }],
      },
      observedHeaders: {
        'X-Ui-Mode': 'auto',
        Authorization: `Bearer ${genuineJwt}`,
      },
    })
    const fromBrowser = extractBrowserBundleSecrets(browserBundle)
    for (const benign of ['user', 'auto', 'concise']) {
      assert.ok(!fromBrowser.includes(benign), `extractBrowserBundleSecrets must exclude "${benign}"`)
    }
    assert.ok(fromBrowser.includes(genuineSessionCookie))
    assert.ok(fromBrowser.includes(genuineJwt))

    // writePersonaSessionFile + personaSecrets also filter polluted scrubTokens (e.g. from login Set-Cookie)
    const dir = mkdtempSync(join(tmpdir(), 'kovo-r3-h10-vault-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const sessionPath = join(dir, 'persona.session')
    const written = writePersonaSessionFile(sessionPath, {
      headerType: 'cookie',
      value: `role=user; mode=auto; summary=concise; app_session=${genuineSessionCookie}`,
      adapterUsed: 'form',
      scrubTokens: ['user', 'auto', 'text', 'system', 'input_text', 'concise', 'role=user', 'summary=concise', genuineCsrfToken],
      bundle,
    } satisfies MintedPersonaSession)

    for (const benign of ['user', 'auto', 'text', 'system', 'input_text', 'concise', 'role=user', 'summary=concise']) {
      assert.ok(!(written.scrubTokens ?? []).includes(benign), `writePersonaSessionFile must drop benign scrubToken "${benign}"`)
    }
    assert.ok((written.scrubTokens ?? []).includes(genuineSessionCookie))
    assert.ok((written.scrubTokens ?? []).includes(genuineCsrfToken))

    const resolved = new Map<string, ResolvedPersona>([[
      'target_user',
      {
        id: 'p_r3_h10',
        handle: 'target_user',
        roleLabel: 'member',
        originAllowlist: ['https://app.test'],
        authKind: 'login',
        headerName: null,
        secret: 'RealPass!9876',
        canaryMarkers: [],
        secretHistory: ['RealPass!9876', 'user', 'auto', 'text', 'system', 'input_text', 'concise', 'role=user'],
        session: written,
      },
    ]])
    const needles = personaSecrets(resolved).map(s => s.value)
    for (const benign of ['user', 'auto', 'text', 'system', 'input_text', 'concise', 'role=user', 'summary=concise']) {
      assert.ok(!needles.includes(benign), `personaSecrets must never emit "${benign}"`)
    }
    for (const genuine of ['RealPass!9876', genuineSessionCookie, genuineCsrfToken, genuineShortAuthSid, genuineJwt, genuineApiKey]) {
      assert.ok(needles.includes(genuine), `personaSecrets must emit genuine secret "${genuine}"`)
    }
  })
})

// ============================================================================
// 2. Content-only outbound provider request scrubbing (provider-stream.ts + provider.ts)
// ============================================================================

describe('R3-H-10: Outbound provider request scrubber preserves protocol fields & keys byte-identically', () => {
  test('protocol-word needles never mutate OpenAI Responses protocol fields, tool schemas, or object keys', () => {
    const genuineSession = 'sess_r3h10_real_secret_9a8b7c6d5e4f'
    const genuineBearer = 'bearer_r3h10_real_tok_112233445566'
    // Adversarially pass protocol words directly as secrets to prove the structural walker itself
    // NEVER touches keys or protocol metadata even in worst-case needle injection.
    const adversarialSecrets: NamedSecret[] = [
      { value: 'user', placeholder: '[persona:p:secret]' },
      { value: 'auto', placeholder: '[persona:p:secret]' },
      { value: 'text', placeholder: '[persona:p:secret]' },
      { value: 'system', placeholder: '[persona:p:secret]' },
      { value: 'input_text', placeholder: '[persona:p:secret]' },
      { value: 'output_text', placeholder: '[persona:p:secret]' },
      { value: 'concise', placeholder: '[persona:p:secret]' },
      { value: 'assistant', placeholder: '[persona:p:secret]' },
      { value: 'developer', placeholder: '[persona:p:secret]' },
      { value: 'required', placeholder: '[persona:p:secret]' },
      { value: 'function', placeholder: '[persona:p:secret]' },
      { value: 'function_call', placeholder: '[persona:p:secret]' },
      { value: 'completed', placeholder: '[persona:p:secret]' },
      { value: genuineSession, placeholder: '[persona:alice:secret]' },
      { value: genuineBearer, placeholder: '[persona:alice:secret]' },
    ]

    const original: Record<string, unknown> = {
      model: 'gpt-5-auto-text',
      stream: true,
      store: false,
      tool_choice: 'auto',
      reasoning: { effort: 'high', summary: 'concise' },
      instructions: `Inspect account with session=${genuineSession}`,
      tools: [
        {
          type: 'function',
          name: 'probe_user_text',
          description: 'Send a probe for user text auto mode',
          parameters: {
            type: 'object',
            properties: {
              role: { type: 'string', enum: ['user', 'system', 'assistant', 'auto'] },
              format: { type: 'string', enum: ['text', 'concise', 'input_text'] },
            },
            required: ['role', 'format'],
            additionalProperties: false,
          },
        },
      ],
      input: [
        { role: 'developer', content: `System note with bearer=${genuineBearer}` },
        {
          role: 'user',
          content: [{ type: 'input_text', text: `Check cookie ${genuineSession}` }],
        },
        {
          type: 'message',
          id: 'msg_user_1',
          role: 'assistant',
          status: 'completed',
          content: [{ type: 'output_text', text: `Observed ${genuineBearer}`, annotations: [] }],
        },
        {
          type: 'function_call',
          id: 'fc_user_1',
          call_id: 'call_auto_1',
          name: 'probe_user_text',
          status: 'completed',
          arguments: JSON.stringify({
            role: 'user',
            format: 'text',
            cookie: genuineSession,
            nested: { user: genuineBearer },
          }),
        },
        {
          type: 'function_call_output',
          call_id: 'call_auto_1',
          output: `HTTP 200 echoed ${genuineSession} and ${genuineBearer}`,
        },
        {
          type: 'reasoning',
          id: 'rs_1',
          status: 'completed',
          encrypted_content: 'enc_user_auto_text_opaque_blob',
          summary: [{ type: 'summary_text', text: `Thinking about ${genuineSession}` }],
        },
      ],
    }

    const scrubbed = scrubOutboundProviderRequest(original, 'sk-test-provider-key-9999', adversarialSecrets)

    // Integrity verifier must report zero violations
    assert.equal(verifyOutboundProviderRequestIntegrity(original, scrubbed), null)

    // All protocol fields, tool schemas, enums, and object keys remain BYTE-IDENTICAL
    assert.deepEqual(Object.keys(scrubbed), Object.keys(original))
    assert.equal(scrubbed.model, original.model)
    assert.equal(scrubbed.tool_choice, 'auto')
    assert.deepEqual(scrubbed.reasoning, { effort: 'high', summary: 'concise' })
    assert.deepEqual(scrubbed.tools, original.tools)

    const items = scrubbed.input as Array<Record<string, unknown>>
    assert.equal(items[0]!.role, 'developer')
    assert.equal(items[1]!.role, 'user')
    assert.equal(((items[1]!.content as Array<Record<string, unknown>>)[0]!).type, 'input_text')
    assert.equal(items[2]!.type, 'message')
    assert.equal(items[2]!.role, 'assistant')
    assert.equal(items[2]!.status, 'completed')
    assert.equal(items[2]!.id, 'msg_user_1')
    assert.equal(((items[2]!.content as Array<Record<string, unknown>>)[0]!).type, 'output_text')
    assert.equal(items[3]!.type, 'function_call')
    assert.equal(items[3]!.call_id, 'call_auto_1')
    assert.equal(items[3]!.name, 'probe_user_text')
    assert.equal(items[4]!.type, 'function_call_output')
    assert.equal(items[4]!.call_id, 'call_auto_1')
    assert.equal(items[5]!.encrypted_content, 'enc_user_auto_text_opaque_blob')
    assert.equal(((items[5]!.summary as Array<Record<string, unknown>>)[0]!).type, 'summary_text')

    // Tool call JSON arguments kept ALL keys intact (`role`, `format`, `cookie`, `nested`, `user`)
    // while scrubbing genuine secret values
    const parsedArgs = JSON.parse(items[3]!.arguments as string) as Record<string, unknown>
    assert.deepEqual(Object.keys(parsedArgs), ['role', 'format', 'cookie', 'nested'])
    assert.deepEqual(Object.keys(parsedArgs.nested as Record<string, unknown>), ['user'])
    assert.equal(parsedArgs.cookie, '[persona:alice:secret]')
    assert.equal((parsedArgs.nested as Record<string, unknown>).user, '[persona:alice:secret]')

    // Content-bearing leaves scrubbed genuine secrets
    assert.equal(scrubbed.instructions, 'Inspect account with session=[persona:alice:secret]')
    assert.equal(items[0]!.content, 'System note with bearer=[persona:alice:secret]')
    assert.ok(!JSON.stringify(scrubbed).includes(genuineSession))
    assert.ok(!JSON.stringify(scrubbed).includes(genuineBearer))
  })

  test('protocol-word needles never mutate Anthropic Messages protocol fields, thinking signatures, or tool_use keys', () => {
    const genuineSecret = 'anth_session_secret_00112233445566'
    const opaqueSignature = 'sig_user_auto_text_cryptographic_signature_blob'
    const adversarialSecrets: NamedSecret[] = [
      { value: 'user', placeholder: '[persona:p:secret]' },
      { value: 'auto', placeholder: '[persona:p:secret]' },
      { value: 'text', placeholder: '[persona:p:secret]' },
      { value: 'thinking', placeholder: '[persona:p:secret]' },
      { value: 'tool_use', placeholder: '[persona:p:secret]' },
      { value: 'tool_result', placeholder: '[persona:p:secret]' },
      { value: genuineSecret, placeholder: '[persona:bob:secret]' },
    ]

    const original: Record<string, unknown> = {
      model: 'claude-auto-text',
      max_tokens: 4096,
      stream: true,
      tool_choice: { type: 'auto' },
      thinking: { type: 'enabled', budget_tokens: 1024, display: 'summarized' },
      system: [{ type: 'text', text: `System prompt ${genuineSecret}`, cache_control: { type: 'ephemeral' } }],
      tools: [{
        name: 'user_text_tool',
        description: 'Tool for user auto text',
        input_schema: {
          type: 'object',
          properties: { user: { type: 'string', enum: ['user', 'auto', 'text'] } },
          required: ['user'],
        },
      }],
      messages: [
        { role: 'user', content: [{ type: 'text', text: `Payload ${genuineSecret}` }] },
        {
          role: 'assistant',
          content: [
            { type: 'thinking', thinking: `Note ${genuineSecret}`, signature: opaqueSignature },
            { type: 'redacted_thinking', data: 'opaque_user_auto_text_redacted_data' },
            {
              type: 'tool_use',
              id: 'toolu_user_1',
              name: 'user_text_tool',
              input: { user: genuineSecret, nested: { text: `val:${genuineSecret}` } },
            },
          ],
        },
        {
          role: 'user',
          content: [{
            type: 'tool_result',
            tool_use_id: 'toolu_user_1',
            is_error: false,
            content: [{ type: 'text', text: `Result ${genuineSecret}` }],
          }],
        },
      ],
    }

    const scrubbed = scrubOutboundProviderRequest(original, 'sk-ant-test-key-1234', adversarialSecrets)
    assert.equal(verifyOutboundProviderRequestIntegrity(original, scrubbed), null)

    assert.equal(scrubbed.model, 'claude-auto-text')
    assert.deepEqual(scrubbed.tool_choice, { type: 'auto' })
    assert.deepEqual(scrubbed.thinking, original.thinking)
    assert.deepEqual(scrubbed.tools, original.tools)

    const sys = scrubbed.system as Array<Record<string, unknown>>
    assert.equal(sys[0]!.type, 'text')
    assert.equal(sys[0]!.text, 'System prompt [persona:bob:secret]')
    assert.deepEqual(sys[0]!.cache_control, { type: 'ephemeral' })

    const msgs = scrubbed.messages as Array<Record<string, unknown>>
    const asstContent = msgs[1]!.content as Array<Record<string, unknown>>
    assert.equal(asstContent[0]!.type, 'thinking')
    assert.equal(asstContent[0]!.signature, opaqueSignature, 'opaque thinking signature must remain byte-identical')
    assert.equal(asstContent[0]!.thinking, 'Note [persona:bob:secret]')
    assert.equal(asstContent[1]!.type, 'redacted_thinking')
    assert.equal(asstContent[1]!.data, 'opaque_user_auto_text_redacted_data')
    assert.equal(asstContent[2]!.type, 'tool_use')
    assert.equal(asstContent[2]!.id, 'toolu_user_1')
    assert.equal(asstContent[2]!.name, 'user_text_tool')
    const toolInput = asstContent[2]!.input as Record<string, unknown>
    assert.deepEqual(Object.keys(toolInput), ['user', 'nested'])
    assert.equal(toolInput.user, '[persona:bob:secret]')
    assert.deepEqual(toolInput.nested, { text: 'val:[persona:bob:secret]' })

    const tr = (msgs[2]!.content as Array<Record<string, unknown>>)[0]!
    assert.equal(tr.type, 'tool_result')
    assert.equal(tr.tool_use_id, 'toolu_user_1')
    assert.equal(((tr.content as Array<Record<string, unknown>>)[0]!).text, 'Result [persona:bob:secret]')
    assert.ok(!JSON.stringify(scrubbed).includes(genuineSecret))
  })

  test('end-to-end provider() round-trip with short protocol-word cookies and genuine session cookie on both responses and messages', async () => {
    const genuineSessionCookie = 'sid_real_e2e_token_abcdef1234567890'
    const personas = new Map<string, ResolvedPersona>([[
      'victim',
      {
        id: 'p_e2e',
        handle: 'victim',
        roleLabel: 'member',
        originAllowlist: ['https://target.example'],
        authKind: 'cookie',
        headerName: null,
        secret: `role=user; mode=auto; fmt=text; scope=system; kind=input_text; sum=concise; session_id=${genuineSessionCookie}`,
        canaryMarkers: [],
      },
    ]])
    const liveSecrets = () => personaSecrets(personas)

    // 1. OpenAI Responses protocol with thinking enabled (emits reasoning.effort + reasoning.summary + role + input_text + tools + enum)
    let capturedResponsesBody: Record<string, unknown> | undefined
    const respProv = provider(
      {
        endpoint: 'https://r3-responses.provider.test/v1',
        model: 'gpt-5-test',
        protocol: 'responses',
        key: 'sk-r3-responses-key-112233',
        thinkingLevel: 'medium',
      },
      'worker-investigation',
      {
        secrets: liveSecrets,
        thinkingLevel: 'medium',
        fetch: async (_input, init) => {
          capturedResponsesBody = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>
          return new Response(responsesTextTurn('ok'), {
            status: 200,
            headers: { 'content-type': 'text/event-stream' },
          })
        },
      },
    )

    const sResp = respProv.models.stream(respProv.model, {
      systemPrompt: `Analyze session ${genuineSessionCookie} with role user and mode auto.`,
      messages: [{
        role: 'user',
        content: `Cookie header had ${genuineSessionCookie} and role=user`,
        timestamp: Date.now(),
      }],
      tools: [{
        name: 'inspect_mode',
        description: 'Inspect target mode.',
        parameters: obj({
          mode: union([lit('auto'), lit('concise'), lit('text')]),
          role: str(),
        }),
      }],
    }, { toolChoice: 'auto' } as never)
    for await (const _ev of sResp) { /* drain */ }
    const rResp = await sResp.result()
    assert.notEqual(rResp.stopReason, 'error', rResp.errorMessage ?? 'unexpected responses error')
    assert.ok(capturedResponsesBody)

    const respInput = capturedResponsesBody!.input as Array<Record<string, unknown>>
    const userMsg = respInput.find(i => i.role === 'user')
    assert.ok(userMsg, 'input[].role === "user" must remain intact')
    const userPart = (userMsg!.content as Array<Record<string, unknown>>)[0]!
    assert.equal(userPart.type, 'input_text', 'input_text type field must remain intact')
    assert.ok(!(userPart.text as string).includes(genuineSessionCookie), 'genuine session cookie must be scrubbed from user text')
    assert.ok((userPart.text as string).includes('[persona:victim:secret]'))
    assert.equal(capturedResponsesBody!.tool_choice, 'auto')
    assert.deepEqual(capturedResponsesBody!.reasoning, { effort: 'medium', summary: 'auto' })
    const respTools = capturedResponsesBody!.tools as Array<{ name: string; parameters: Record<string, unknown> }>
    assert.equal(respTools[0]!.name, 'inspect_mode')
    assert.ok(!JSON.stringify(respTools[0]!.parameters).includes('[persona:'), 'tool schema must never contain persona placeholders')
    assert.ok(!JSON.stringify(capturedResponsesBody).includes(genuineSessionCookie))

    // 2. Anthropic Messages protocol
    let capturedMessagesBody: Record<string, unknown> | undefined
    const msgProv = provider(
      {
        endpoint: 'https://r3-messages.provider.test/v1',
        model: 'claude-test',
        protocol: 'messages',
        key: 'sk-ant-r3-messages-key-445566',
        thinkingLevel: 'off',
      },
      'worker-investigation',
      {
        secrets: liveSecrets,
        thinkingLevel: 'off',
        fetch: async (_input, init) => {
          capturedMessagesBody = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>
          return new Response(messagesTextTurn('ok'), {
            status: 200,
            headers: { 'content-type': 'text/event-stream' },
          })
        },
      },
    )

    const sMsg = msgProv.models.stream(msgProv.model, {
      systemPrompt: `System prompt with ${genuineSessionCookie}`,
      messages: [{
        role: 'user',
        content: `Inspect ${genuineSessionCookie} for user`,
        timestamp: Date.now(),
      }],
      tools: [{
        name: 'inspect_mode',
        description: 'Inspect target mode.',
        parameters: obj({
          mode: union([lit('auto'), lit('text')]),
        }),
      }],
    })
    for await (const _ev of sMsg) { /* drain */ }
    const rMsg = await sMsg.result()
    assert.notEqual(rMsg.stopReason, 'error', rMsg.errorMessage ?? 'unexpected messages error')
    assert.ok(capturedMessagesBody)
    const anthMsgs = capturedMessagesBody!.messages as Array<Record<string, unknown>>
    assert.equal(anthMsgs[0]!.role, 'user')
    assert.ok(!JSON.stringify(capturedMessagesBody).includes(genuineSessionCookie))
    assert.ok(JSON.stringify(capturedMessagesBody).includes('[persona:victim:secret]'))
  })

  test('null-prototype objects and reserved keys (__proto__, constructor, toString, hasOwnProperty) are handled safely', () => {
    const secret = 'secret_null_proto_token_99887766'
    const secrets: NamedSecret[] = [{ value: secret, placeholder: '[persona:np:secret]' }]

    const nullProtoInput = Object.create(null) as Record<string, unknown>
    nullProtoInput['constructor'] = `ctor:${secret}`
    nullProtoInput['toString'] = `str:${secret}`
    nullProtoInput['hasOwnProperty'] = `has:${secret}`
    Object.defineProperty(nullProtoInput, '__proto__', {
      value: { nested: `proto:${secret}` },
      writable: true,
      enumerable: true,
      configurable: true,
    })

    const payload = Object.create(null) as Record<string, unknown>
    payload.model = 'test-model'
    payload.messages = [
      {
        role: 'assistant',
        content: [{
          type: 'tool_use',
          id: 'toolu_np_1',
          name: 'custom_tool',
          input: nullProtoInput,
        }],
      },
    ]

    const scrubbed = scrubOutboundProviderRequest(payload, 'sk-np-key-1234', secrets)
    assert.equal(verifyOutboundProviderRequestIntegrity(payload, scrubbed), null)
    const msg = (scrubbed.messages as Array<Record<string, unknown>>)[0]!
    const block = (msg.content as Array<Record<string, unknown>>)[0]!
    const outInput = block.input as Record<string, unknown>
    assert.equal(outInput['constructor'], 'ctor:[persona:np:secret]')
    assert.equal(outInput['toString'], 'str:[persona:np:secret]')
    assert.equal(outInput['hasOwnProperty'], 'has:[persona:np:secret]')
    assert.equal(Object.prototype.hasOwnProperty.call(outInput, '__proto__'), true)
    assert.deepEqual(outInput['__proto__'], { nested: 'proto:[persona:np:secret]' })
    assert.equal(({} as Record<string, unknown>).nested, undefined, 'Object.prototype must never be polluted')

    // Generic scrubExactSecretsValue also handles null-prototype objects without rewriting keys
    const generic = Object.create(null) as Record<string, unknown>
    generic[secret] = `val:${secret}`
    generic['toString'] = `s:${secret}`
    const scrubbedGeneric = scrubExactSecretsValue(generic, 'sk-np-key-1234', secrets) as Record<string, unknown>
    assert.equal(Object.prototype.hasOwnProperty.call(scrubbedGeneric, secret), true, 'scrubExactSecretsValue must not rewrite object keys')
    assert.equal(scrubbedGeneric[secret], 'val:[persona:np:secret]')
    assert.equal(scrubbedGeneric['toString'], 's:[persona:np:secret]')
  })
})

// ============================================================================
// 3. Integrity verification & clear local-mutation 400 diagnostics
// ============================================================================

describe('R3-H-10: Payload integrity verification & local-mutation HTTP 400 diagnostics', () => {
  test('verifyOutboundProviderRequestIntegrity catches mutated protocol fields and placeholder leakage', () => {
    const orig: Record<string, unknown> = {
      model: 'gpt-5',
      tool_choice: 'auto',
      reasoning: { effort: 'high', summary: 'concise' },
      tools: [{ type: 'function', name: 'f', parameters: { type: 'object', properties: {} } }],
      input: [
        { role: 'user', content: [{ type: 'input_text', text: 'hello' }] },
      ],
    }

    assert.equal(verifyOutboundProviderRequestIntegrity(orig, structuredClone(orig)), null)

    const badRole = structuredClone(orig)
    ;(badRole.input as Array<Record<string, unknown>>)[0]!.role = '[persona:a:secret]'
    assert.equal(verifyOutboundProviderRequestIntegrity(orig, badRole), 'input[0].role')

    const badToolChoice = structuredClone(orig)
    badToolChoice.tool_choice = '[persona:a:secret]'
    assert.equal(verifyOutboundProviderRequestIntegrity(orig, badToolChoice), 'tool_choice')

    const badContentType = structuredClone(orig)
    ;((badContentType.input as Array<Record<string, unknown>>)[0]!.content as Array<Record<string, unknown>>)[0]!.type = '[persona:a:secret]'
    assert.equal(verifyOutboundProviderRequestIntegrity(orig, badContentType), 'input[0].content[0].type')

    const badReasoning = structuredClone(orig)
    ;(badReasoning.reasoning as Record<string, unknown>).summary = '[persona:a:secret]'
    assert.equal(verifyOutboundProviderRequestIntegrity(orig, badReasoning), 'reasoning')
  })

  test('provider() surfaces a clear local-mutation diagnostic when upstream returns HTTP 400 citing schema/placeholder failure after local scrub', async () => {
    const secret = 'sess_400_diag_secret_9876543210'
    const { models, model } = provider(
      {
        endpoint: 'https://diag-400.provider.test/v1',
        model: 'gpt-diag',
        protocol: 'responses',
        key: 'sk-diag-key-123456',
      },
      'worker-investigation',
      {
        secrets: [{ value: secret, placeholder: '[persona:diag:secret]' }],
        fetch: async () => new Response(
          JSON.stringify({
            error: {
              type: 'invalid_request_error',
              message: "Invalid value for 'input[0].role': '[persona:diag:secret]'. Expected one of 'user', 'assistant', 'system'.",
            },
          }),
          { status: 400, headers: { 'content-type': 'application/json' } },
        ),
      },
    )

    const s = models.stream(model, {
      systemPrompt: 'Test.',
      messages: [{ role: 'user', content: `token=${secret}`, timestamp: Date.now() }],
      tools: [],
    })
    for await (const _ev of s) { /* drain */ }
    const res = await s.result()
    assert.equal(res.stopReason, 'error')
    assert.match(res.errorMessage ?? '', /Local provider request mutation caused HTTP 400/i)
    assert.match(res.errorMessage ?? '', /input\[0\]\.role/)
    assert.equal(classifyProviderFailure(res.errorMessage ?? ''), null)
  })
})
