/**
 * Fast class-level regression guards for WS-8 (CLAUDE_AUDIT_R4):
 *  - R4-H-2: Provenance-tiered exact-secret needle builder (`primary_credential` vs `heuristic_derived`)
 *            so short/weak/dictionary primary operator credentials are always redacted across
 *            broker/tool-result/provider boundaries while target-derived tokens stay strictly gated.
 *  - R4-H-17: Structural content-only inbound provider stream scrubber + integrity check +
 *            cookie-name quality gate on target-emitted login `Set-Cookie` `scrubTokens`.
 *  - R4-H-3: Mandatory host-derived `scopePolicy` and `modifiedPaths` wired in production
 *            `PersonaAuthManager.authenticateBrowserSession`, non-GET/HEAD method blocking on
 *            target origins in the unattended refresher, and project-scope validation on
 *            `browser_session` `originAllowlist`.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import { newRun } from '../src/domain.ts'
import {
  BrowserSessionRefreshBlockedError,
  evaluateBrowserSessionProxyOrigin,
  refreshBrowserSession,
  registerBrowserSessionPersonaFromAction,
  resolveBrowserSessionEgressPolicy,
} from '../src/server/browser-session-auth.ts'
import type {
  BrowserSessionChromiumLaunchOptions,
  PlaywrightBrowserLike,
  PlaywrightRouteLike,
  PlaywrightStorageState,
} from '../src/server/browser-session-auth.ts'
import { createEgressSanitizer } from '../src/server/egress-sanitizer.ts'
import { PersonaAuthManager } from '../src/server/persona-auth.ts'
import {
  assertOriginsWithinProjectScope,
  buildPersonaSecretNeedles,
  createBrowserSessionPersona,
  createProjectPersona,
  createSecretNeedleBuilder,
  extractScrubbableCookieMapNeedles,
  personaSecrets,
  resolveRunPersonas,
} from '../src/server/persona-vault.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  sanitizeProviderStream,
  sanitizeProviderValue,
  scrubOutboundProviderRequest,
  verifyInboundProviderFrameIntegrity,
} from '../src/server/provider-stream.ts'
import { redact } from '../src/server/redact.ts'
import type { NamedSecret } from '../src/server/redact.ts'
import { assignments, brokerExchanges } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'

function streamFromText(text: string, chunkSize = 11): ReadableStream<Uint8Array> {
  const buf = Buffer.from(text, 'utf8')
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (let i = 0; i < buf.length; i += chunkSize) {
        controller.enqueue(buf.subarray(i, i + chunkSize))
      }
      controller.close()
    },
  })
}

function parseSseFrames(wire: string): Array<{ eventLine?: string; data?: Record<string, unknown> | '[DONE]' }> {
  return wire
    .split('\n\n')
    .map(chunk => chunk.trim())
    .filter(Boolean)
    .map(chunk => {
      const lines = chunk.split('\n')
      const eventLine = lines.find(l => l.startsWith('event:'))
      const dataLine = lines.find(l => l.startsWith('data:'))
      const rawData = dataLine?.slice(5).trim()
      const data = rawData === '[DONE]'
        ? '[DONE]'
        : rawData
          ? (JSON.parse(rawData) as Record<string, unknown>)
          : undefined
      return { eventLine, data }
    })
}

function makeStubBrowserLauncher(capture: {
  launchCount: number
  routeHandler?: (route: PlaywrightRouteLike) => Promise<void> | void
  visitedUrls: string[]
}) {
  return async (_opts: BrowserSessionChromiumLaunchOptions): Promise<PlaywrightBrowserLike> => {
    capture.launchCount += 1
    return {
      async newContext(ctxOpts) {
        const seeded = (ctxOpts?.storageState as PlaywrightStorageState | undefined) ?? { cookies: [], origins: [] }
        let currentUrl = ''
        const page = {
          async goto(url: string) {
            currentUrl = url
            capture.visitedUrls.push(url)
          },
          async waitForLoadState() {},
          async waitForTimeout() {},
          url: () => currentUrl,
          on() {},
          async close() {},
        }
        return {
          async newPage() { return page },
          async addInitScript() {},
          async route(_pattern: string, handler: (route: PlaywrightRouteLike) => Promise<void> | void) {
            capture.routeHandler = handler
          },
          async routeWebSocket() {},
          async storageState() { return seeded },
          async close() {},
        }
      },
      async close() {},
    }
  }
}

// ============================================================================
// 1. R4-H-2: Provenance-Tiered Needle Builder & Weak Primary Credential Redaction
// ============================================================================

describe('R4-H-2: Provenance-tiered secret needle builder preserves weak primary operator credentials', () => {
  test('short 6-char bearer, dictionary login password, and generic 12-hex cookie all yield exact needles and are redacted on broker/tool/provider boundaries', () => {
    const shortBearer = 'tok42a'
    const dictPassword = 'password'
    const genericHexCookieVal = 'a1b2c3d4e5f6'
    const genericCookieHeader = `my_c=${genericHexCookieVal}`
    const lowEntropyHeaderKey = '11111111'

    const resolved = new Map<string, ResolvedPersona>([
      ['short_bearer', {
        id: 'p-bearer',
        handle: 'short_bearer',
        roleLabel: 'member',
        originAllowlist: ['https://app.northstar.example'],
        authKind: 'bearer',
        headerName: null,
        secret: shortBearer,
        secretHistory: [shortBearer, 'old99z'],
        canaryMarkers: [],
      }],
      ['dict_login', {
        id: 'p-login',
        handle: 'dict_login',
        roleLabel: 'member',
        originAllowlist: ['https://app.northstar.example'],
        authKind: 'login',
        headerName: null,
        secret: dictPassword,
        secretHistory: [dictPassword],
        session: {
          headerType: 'bearer',
          value: 'minted',
          adapterUsed: 'json',
        },
        canaryMarkers: [],
      }],
      ['hex_cookie', {
        id: 'p-cookie',
        handle: 'hex_cookie',
        roleLabel: 'member',
        originAllowlist: ['https://app.northstar.example'],
        authKind: 'cookie',
        headerName: null,
        secret: genericCookieHeader,
        secretHistory: [genericCookieHeader],
        canaryMarkers: [],
      }],
      ['weak_header', {
        id: 'p-header',
        handle: 'weak_header',
        roleLabel: 'member',
        originAllowlist: ['https://app.northstar.example'],
        authKind: 'header',
        headerName: 'X-Api-Key',
        secret: lowEntropyHeaderKey,
        canaryMarkers: [],
      }],
    ])

    const secrets = personaSecrets(resolved)
    const values = secrets.map(s => s.value)
    assert.ok(values.includes(shortBearer), '6-char primary bearer token must yield an exact needle')
    assert.ok(values.includes('old99z'), 'rotated static bearer secretHistory must yield an exact needle')
    assert.ok(values.includes(dictPassword), 'dictionary login password must yield an exact needle')
    assert.ok(values.includes('minted'), 'short minted non-cookie session token must yield an exact needle')
    assert.ok(values.includes(genericHexCookieVal), 'non-auth-named 12-hex cookie value must yield an exact needle')
    assert.ok(values.includes(genericCookieHeader), 'configured Cookie header must yield an exact needle')
    assert.ok(values.includes(lowEntropyHeaderKey), 'low-entropy primary header credential must yield an exact needle')

    // Shared builder supports WS-3 custom placeholders (`[redacted:<handle>]`)
    const kernelSecrets = buildPersonaSecretNeedles(resolved, {
      placeholderFor: p => `[redacted:${p.handle}]`,
      refreshFromDisk: false,
    })
    assert.ok(
      kernelSecrets.some(s => s.value === shortBearer && s.placeholder === '[redacted:short_bearer]'),
      'buildPersonaSecretNeedles must support custom placeholderFor for WS-3 getKernelSecrets',
    )

    // Unkeyed CSV/echo reflection across broker exchange / worker RPC / tool-result / outbound provider boundaries
    const unkeyedReflection = `row,1,${shortBearer},${dictPassword},${genericHexCookieVal},${lowEntropyHeaderKey}`
    const sanitizer = createEgressSanitizer({ secrets })

    const scrubbedBroker = redact(unkeyedReflection, secrets)
    const scrubbedWorkerRpc = sanitizer.redactText(unkeyedReflection, 'worker_rpc')
    const scrubbedToolResult = sanitizer.redactText(unkeyedReflection, 'llm_context')
    for (const raw of [shortBearer, dictPassword, genericHexCookieVal, lowEntropyHeaderKey]) {
      assert.ok(!scrubbedBroker.includes(raw), `broker redact boundary leaked primary credential "${raw}"`)
      assert.ok(!scrubbedWorkerRpc.includes(raw), `worker_rpc boundary leaked primary credential "${raw}"`)
      assert.ok(!scrubbedToolResult.includes(raw), `tool-result/llm_context boundary leaked primary credential "${raw}"`)
    }

    const outboundReq = scrubOutboundProviderRequest(
      {
        model: 'gpt-5-test',
        tool_choice: 'auto',
        input: [
          { role: 'user', content: [{ type: 'input_text', text: unkeyedReflection }] },
        ],
      },
      'sk-provider-key-r4h2',
      secrets,
    )
    const outboundWire = JSON.stringify(outboundReq)
    for (const raw of [shortBearer, dictPassword, genericHexCookieVal, lowEntropyHeaderKey]) {
      assert.ok(!outboundWire.includes(raw), `outbound provider request leaked primary credential "${raw}"`)
    }
  })

  test('heuristic_derived tier still rejects benign preference cookies and protocol-substring cookies', () => {
    const builder = createSecretNeedleBuilder()
    assert.equal(builder.addCookiePair('[p]', 'prefs', 'dark_mode_enabled', 'heuristic_derived'), false)
    assert.equal(builder.addCookiePair('[p]', 'role', 'user', 'heuristic_derived'), false)
    assert.equal(builder.addCookiePair('[p]', 'x_track', 'response.output_text.delta', 'heuristic_derived'), false)
    assert.equal(builder.addCookiePair('[p]', 'x_proto', 'response.output_item.added', 'heuristic_derived'), false)
    assert.equal(builder.addCookiePair('[p]', 'x_anth', 'content_block_delta', 'heuristic_derived'), false)
    assert.equal(builder.addRaw('[p]', 'response.output_text.delta', 'heuristic_derived'), false)
    assert.equal(builder.addRaw('[p]', 'content_block_delta', 'heuristic_derived'), false)

    // Genuine auth-relevant session cookie passes heuristic_derived
    assert.equal(builder.addCookiePair('[p]', 'app_session', 'sess_real_9f8e7d6c5b4a3210', 'heuristic_derived'), true)
    assert.deepEqual(builder.values(), ['sess_real_9f8e7d6c5b4a3210'])
  })
})

// ============================================================================
// 2. R4-H-17: Structural Inbound Stream Scrubber + Integrity Check + Set-Cookie Quality
// ============================================================================

describe('R4-H-17: Inbound provider stream sanitizer preserves protocol structure & rejects Set-Cookie protocol substrings', () => {
  test('protocol-substring needles never alter OpenAI Responses or Anthropic Messages SSE type, event, or JSON keys', async () => {
    const providerKey = 'sk-r4h17-provider-key-998877'
    const realSecret = 'sess_r4h17_real_secret_abcdef123456'
    // Adversarial needle set containing exact SSE event names, prefixes, and JSON key names
    const adversarialSecrets: NamedSecret[] = [
      { value: 'response.output_text', placeholder: '[persona:evil:secret]' },
      { value: 'response.output_text.delta', placeholder: '[persona:evil:secret]' },
      { value: 'response.output_item.added', placeholder: '[persona:evil:secret]' },
      { value: 'response.completed', placeholder: '[persona:evil:secret]' },
      { value: 'content_block_delta', placeholder: '[persona:evil:secret]' },
      { value: 'content_block_start', placeholder: '[persona:evil:secret]' },
      { value: 'message_start', placeholder: '[persona:evil:secret]' },
      { value: 'message_delta', placeholder: '[persona:evil:secret]' },
      { value: 'message_stop', placeholder: '[persona:evil:secret]' },
      { value: 'text_delta', placeholder: '[persona:evil:secret]' },
      { value: 'output_text', placeholder: '[persona:evil:secret]' },
      { value: 'completed', placeholder: '[persona:evil:secret]' },
      { value: 'assistant', placeholder: '[persona:evil:secret]' },
      { value: 'end_turn', placeholder: '[persona:evil:secret]' },
      { value: 'type', placeholder: '[persona:evil:secret]' },
      { value: 'delta', placeholder: '[persona:evil:secret]' },
      { value: 'status', placeholder: '[persona:evil:secret]' },
      { value: realSecret, placeholder: '[persona:alice:secret]' },
    ]

    // 1. OpenAI Responses SSE stream
    const responsesFrames = [
      { type: 'response.created', response: { id: 'resp_1', status: 'in_progress' } },
      {
        type: 'response.output_item.added',
        output_index: 0,
        item: { type: 'message', id: 'msg_1', role: 'assistant', status: 'in_progress', content: [] },
      },
      { type: 'response.output_text.delta', output_index: 0, content_index: 0, delta: `Leaked ${realSecret} here.` },
      {
        type: 'response.output_item.done',
        output_index: 0,
        item: {
          type: 'message',
          id: 'msg_1',
          role: 'assistant',
          status: 'completed',
          content: [{ type: 'output_text', text: `Leaked ${realSecret} here.` }],
        },
      },
      {
        type: 'response.completed',
        response: { id: 'resp_1', status: 'completed', output: [] },
      },
    ]
    const responsesWire =
      responsesFrames.map(ev => `event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`).join('') +
      'data: [DONE]\n\n'

    const sanitizedRespWire = await new Response(
      sanitizeProviderStream(streamFromText(responsesWire), providerKey, 'responses', adversarialSecrets),
    ).text()
    const parsedResp = parseSseFrames(sanitizedRespWire)
    assert.equal(parsedResp.length, responsesFrames.length + 1)
    for (let i = 0; i < responsesFrames.length; i++) {
      assert.equal(parsedResp[i]!.eventLine, `event: ${responsesFrames[i]!.type}`, 'SSE event: line must remain intact')
      const data = parsedResp[i]!.data as Record<string, unknown>
      assert.equal(data.type, responsesFrames[i]!.type, 'JSON type field must remain intact')
      assert.deepEqual(Object.keys(data), Object.keys(responsesFrames[i]!), 'JSON keys must never be rewritten')
    }
    const deltaFrame = parsedResp[2]!.data as { delta: string }
    assert.equal(deltaFrame.delta, 'Leaked [persona:alice:secret] here.')
    assert.ok(!sanitizedRespWire.includes(realSecret))

    // 2. Anthropic Messages SSE stream
    const messagesFrames = [
      {
        type: 'message_start',
        message: { id: 'msg_a1', type: 'message', role: 'assistant', model: 'claude-test', content: [] },
      },
      { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
      { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: `Found ${realSecret}!` } },
      { type: 'content_block_stop', index: 0 },
      { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 5 } },
      { type: 'message_stop' },
    ]
    const messagesWire = messagesFrames
      .map(ev => `event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`)
      .join('')

    const sanitizedMsgWire = await new Response(
      sanitizeProviderStream(streamFromText(messagesWire), providerKey, 'messages', adversarialSecrets),
    ).text()
    const parsedMsg = parseSseFrames(sanitizedMsgWire)
    assert.equal(parsedMsg.length, messagesFrames.length)
    for (let i = 0; i < messagesFrames.length; i++) {
      assert.equal(parsedMsg[i]!.eventLine, `event: ${messagesFrames[i]!.type}`)
      const data = parsedMsg[i]!.data as Record<string, unknown>
      assert.equal(data.type, messagesFrames[i]!.type)
    }
    const msgDelta = parsedMsg[2]!.data as { delta: { type: string; text: string } }
    assert.equal(msgDelta.delta.type, 'text_delta')
    assert.equal(msgDelta.delta.text, 'Found [persona:alice:secret]!')
    const stopDelta = parsedMsg[4]!.data as { delta: { stop_reason: string } }
    assert.equal(stopDelta.delta.stop_reason, 'end_turn')
    assert.ok(!sanitizedMsgWire.includes(realSecret))

    // 3. Direct sanitizeProviderValue also preserves keys & protocol fields
    const direct = sanitizeProviderValue(
      { type: 'response.output_text.delta', status: 'in_progress', delta: `note=${realSecret}` },
      providerKey,
      undefined,
      adversarialSecrets,
    ) as Record<string, unknown>
    assert.deepEqual(Object.keys(direct), ['type', 'status', 'delta'])
    assert.equal(direct.type, 'response.output_text.delta')
    assert.equal(direct.status, 'in_progress')
    assert.equal(direct.delta, 'note=[persona:alice:secret]')
  })

  test('verifyInboundProviderFrameIntegrity fails loudly on mutated protocol keys or fields', () => {
    const orig: Record<string, unknown> = {
      type: 'content_block_delta',
      index: 0,
      delta: { type: 'text_delta', text: 'hello' },
    }
    assert.equal(verifyInboundProviderFrameIntegrity(orig, structuredClone(orig)), null)

    const badType = structuredClone(orig)
    badType.type = '[persona:evil:secret]'
    assert.equal(verifyInboundProviderFrameIntegrity(orig, badType), 'frame.type')

    const badDeltaType = structuredClone(orig)
    ;(badDeltaType.delta as Record<string, unknown>).type = '[persona:evil:secret]'
    assert.equal(verifyInboundProviderFrameIntegrity(orig, badDeltaType), 'frame.delta.type')

    const badKeys: Record<string, unknown> = {
      '[persona:evil:secret]': 'content_block_delta',
      index: 0,
      delta: { type: 'text_delta', text: 'hello' },
    }
    assert.equal(verifyInboundProviderFrameIntegrity(orig, badKeys), 'frame.keys')
  })

  test('target-emitted login Set-Cookie protocol substrings never enter scrubTokens or personaSecrets', async t => {
    const cookies = new Map<string, string>([
      ['x_track', 'response.output_text.delta'],
      ['x_evil_proto', 'content_block_delta'],
      ['x_custom', 'response.output_item.added'],
      ['session_id', 'real_login_sid_a1b2c3d4e5f6'],
    ])
    const extracted = extractScrubbableCookieMapNeedles(cookies)
    assert.ok(!extracted.includes('response.output_text.delta'))
    assert.ok(!extracted.includes('content_block_delta'))
    assert.ok(!extracted.includes('response.output_item.added'))
    assert.ok(extracted.includes('real_login_sid_a1b2c3d4e5f6'))

    // Live JSON login through PersonaAuthManager with target-injected protocol-substring Set-Cookie
    const dir = mkdtempSync(join(tmpdir(), 'kovo-r4-h17-login-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const store = new Store(dir, { ftsMode: 'preview' })
    t.after(() => store.close())

    const project = store.createProject({
      requestId: randomUUID(),
      name: 'R4-H-17 Login Cookie Guard',
      seeds: ['https://app.northstar.example'],
      environment: 'public',
    })
    const created = createProjectPersona(store, {
      requestId: randomUUID(),
      projectId: project.id,
      handle: 'json_login_user',
      roleLabel: 'member',
      originAllowlist: ['https://app.northstar.example'],
      authKind: 'login',
      loginConfig: {
        adapter: 'json',
        email: 'alice@northstar.example',
        loginUrl: 'https://app.northstar.example/api/login',
      },
      secret: 'CorrectHorseBattery1!',
      canaryMarkers: [],
    })

    const authManager = new PersonaAuthManager({
      resolveHost: async () => ['93.184.216.34'],
      fetchImpl: async () => {
        const headers = new Headers({ 'content-type': 'application/json' })
        headers.append('set-cookie', 'x_track=response.output_text.delta; Path=/')
        headers.append('set-cookie', 'x_anth=content_block_delta; Path=/')
        headers.append('set-cookie', 'app_session=real_login_sid_a1b2c3d4e5f6; Path=/; HttpOnly')
        return new Response(JSON.stringify({ ok: true }), { status: 200, headers })
      },
    })
    t.after(() => authManager.stopAll())

    await authManager.authenticatePersona(store, project.id, created.id)
    const resolved = resolveRunPersonas(store, project.id, [created.id])
    const needles = personaSecrets(resolved).map(s => s.value)
    assert.ok(!needles.includes('response.output_text.delta'), 'target Set-Cookie protocol substring must not become a needle')
    assert.ok(!needles.includes('content_block_delta'), 'target Set-Cookie protocol substring must not become a needle')
    assert.ok(needles.includes('real_login_sid_a1b2c3d4e5f6'), 'genuine session cookie must become a needle')
    assert.ok(needles.includes('CorrectHorseBattery1!'), 'primary login password must become a needle')
  })
})

// ============================================================================
// 3. R4-H-3: Mandatory Host-Derived Refresher Inputs, Method Gating & Scope Validation
// ============================================================================

describe('R4-H-3: Production refresher forwards host-derived scopePolicy & modifiedPaths and blocks mutations', () => {
  test('refreshBrowserSession fails closed when ScopePolicy is missing in production', async () => {
    await assert.rejects(
      () => refreshBrowserSession({
        storageState: { cookies: [], origins: [] },
        targetOrigin: 'https://app.northstar.example',
        verifyPath: '/dashboard',
      }),
      err => err instanceof BrowserSessionRefreshBlockedError && err.code === 'SCOPE_POLICY_REQUIRED',
    )

    // Even with a stub launcher, requireScopePolicy: true fails closed
    await assert.rejects(
      () => refreshBrowserSession({
        storageState: { cookies: [], origins: [] },
        targetOrigin: 'https://app.northstar.example',
        verifyPath: '/dashboard',
        requireScopePolicy: true,
        launchBrowser: makeStubBrowserLauncher({ launchCount: 0, visitedUrls: [] }),
      }),
      err => err instanceof BrowserSessionRefreshBlockedError && err.code === 'SCOPE_POLICY_REQUIRED',
    )
  })

  test('evaluateBrowserSessionProxyOrigin blocks non-GET/HEAD mutations to target origins while allowing approved IdP POST', () => {
    const policy = resolveBrowserSessionEgressPolicy({
      targetUrl: new URL('https://app.northstar.example'),
      allowLocalLab: false,
      allowedOrigins: ['https://app.northstar.example'],
      idpOrigins: ['https://idp.northstar-auth.example'],
      scopePolicy: {
        mode: 'staging_isolated',
        targetOrigins: ['https://app.northstar.example'],
        authOrigins: ['https://idp.northstar-auth.example'],
        routeDenylist: ['/admin/delete-all'],
      },
    })

    // GET & HEAD on target allowed (non-denylisted)
    assert.equal(evaluateBrowserSessionProxyOrigin(policy, 'https://app.northstar.example', 'GET', new URL('https://app.northstar.example/dashboard')).allowed, true)
    assert.equal(evaluateBrowserSessionProxyOrigin(policy, 'https://app.northstar.example', 'HEAD', new URL('https://app.northstar.example/health')).allowed, true)

    // Denylisted route blocked even on GET
    assert.equal(evaluateBrowserSessionProxyOrigin(policy, 'https://app.northstar.example', 'GET', new URL('https://app.northstar.example/admin/delete-all')).allowed, false)

    // Arbitrary non-GET/HEAD requests on target origin blocked!
    for (const [method, path] of [
      ['POST', '/api/users'],
      ['POST', '/comments'],
      ['POST', '/graphql'],
      ['PUT', '/api/profile'],
      ['PATCH', '/api/settings'],
      ['DELETE', '/api/projects/1'],
    ] as const) {
      const verdict = evaluateBrowserSessionProxyOrigin(policy, 'https://app.northstar.example', method, new URL(`https://app.northstar.example${path}`))
      assert.equal(verdict.allowed, false, `${method} ${path} to target origin MUST be blocked in unattended refresher`)
    }

    // Approved IdP token endpoint POST allowed, while IdP DELETE is blocked
    assert.equal(evaluateBrowserSessionProxyOrigin(policy, 'https://idp.northstar-auth.example', 'POST', new URL('https://idp.northstar-auth.example/oauth/token')).allowed, true)
    assert.equal(evaluateBrowserSessionProxyOrigin(policy, 'https://idp.northstar-auth.example', 'DELETE', new URL('https://idp.northstar-auth.example/oauth/token')).allowed, false)
  })

  test('browser_session persona creation validates originAllowlist against project scope', t => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-r4-h3-scope-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const store = new Store(dir, { ftsMode: 'preview' })
    t.after(() => store.close())

    const project = store.createProject({
      requestId: randomUUID(),
      name: 'Northstar Scoped Project',
      seeds: ['https://app.northstar.example'],
      environment: 'public',
    })
    const sampleState: PlaywrightStorageState = {
      cookies: [{
        name: 'app_session',
        value: 'sess_scope_test_1234567890',
        domain: 'app.northstar.example',
        path: '/',
        expires: -1,
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
      }],
      origins: [],
    }

    // Out-of-scope origin MUST be rejected
    assert.throws(
      () => createBrowserSessionPersona(store, {
        requestId: randomUUID(),
        projectId: project.id,
        handle: 'bad-origin-user',
        roleLabel: 'member',
        originAllowlist: ['https://unrelated-evil.example'],
        storageState: sampleState,
      }),
      /outside the project scope/i,
    )
    assert.throws(
      () => registerBrowserSessionPersonaFromAction(store, {
        requestId: randomUUID(),
        projectId: project.id,
        handle: 'bad-action-user',
        roleLabel: 'member',
        originAllowlist: ['https://app.northstar.example', 'https://attacker.example'],
        storageState: sampleState,
      }),
      /outside the project scope/i,
    )

    // Multi-tenant PSL sibling must NEVER be admitted
    const pslProject = store.createProject({
      requestId: randomUUID(),
      name: 'PSL Tenant Project',
      seeds: ['https://tenant-a.vercel.app'],
      environment: 'public',
    })
    assert.throws(
      () => assertOriginsWithinProjectScope(store, pslProject.id, ['https://tenant-b.vercel.app']),
      /outside the project scope/i,
    )

    // Same-apex first-party sibling on non-PSL domain IS admitted
    assert.deepEqual(
      assertOriginsWithinProjectScope(store, project.id, ['https://app.northstar.example', 'https://api.northstar.example']),
      ['https://app.northstar.example', 'https://api.northstar.example'],
    )
  })

  test('production PersonaAuthManager.authenticatePersona forwards ScopePolicy (aborting denylisted route & non-GET target mutations) and blocks run-mutated verifyPath with BrowserSessionRefreshBlockedError', async t => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-r4-h3-contract-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const store = new Store(dir, { ftsMode: 'preview' })
    t.after(() => store.close())

    const targetOrigin = 'https://app.northstar.example'
    const idpOrigin = 'https://idp.northstar-auth.example'
    const project = store.createProject({
      requestId: randomUUID(),
      name: 'Northstar Refresher Contract',
      seeds: [targetOrigin],
      environment: 'public',
    })

    const storageState: PlaywrightStorageState = {
      cookies: [{
        name: 'app_session',
        value: 'sess_contract_valid_99887766',
        domain: 'app.northstar.example',
        path: '/',
        expires: -1,
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
      }],
      origins: [],
    }
    const persona = registerBrowserSessionPersonaFromAction(store, {
      requestId: randomUUID(),
      projectId: project.id,
      handle: 'alice-browser',
      roleLabel: 'member',
      originAllowlist: [targetOrigin],
      storageState,
      verifyPath: '/dashboard',
      idpOrigins: [idpOrigin],
    })

    // Start an active run with a routeDenylist on the target
    const createdRun = store.createRun(newRun.parse({
      requestId: randomUUID(),
      projectId: project.id,
      goal: 'Verify refresher host-derived ScopePolicy and modifiedPaths',
      capabilityTier: 2,
      approvedPersonaIds: [persona.id],
    }))
    const run = store.setRouteDenylist(
      store.setEnvironmentMode(store.run(createdRun.id), 'staging_isolated'),
      ['/admin/delete-all'],
    )

    const stubCapture = { launchCount: 0, visitedUrls: [] as string[], routeHandler: undefined as ((route: PlaywrightRouteLike) => Promise<void> | void) | undefined }
    const authManager = new PersonaAuthManager({
      launchBrowserSession: makeStubBrowserLauncher(stubCapture),
      resolveHost: async () => ['93.184.216.34'],
    })
    t.after(() => authManager.stopAll())

    // 1. Initial authentication succeeds when /dashboard has not been mutated
    const authRes = await authManager.authenticatePersona(store, project.id, persona.id, undefined, run.id)
    assert.equal(authRes.adapterUsed, 'browser_session')
    assert.equal(stubCapture.launchCount, 1)
    assert.deepEqual(stubCapture.visitedUrls, [`${targetOrigin}/dashboard`])
    assert.ok(stubCapture.routeHandler, 'Expected production authenticateBrowserSession to install context.route guard')

    const evalRoute = async (url: string, method = 'GET') => {
      let aborted = false
      let continued = false
      await stubCapture.routeHandler!({
        request: () => ({ url: () => url, method: () => method, headers: () => ({}) }),
        abort: async () => { aborted = true },
        continue: async () => { continued = true },
      })
      return { aborted, continued }
    }

    // ScopePolicy routeDenylist is enforced on the live production refresher route guard
    assert.deepEqual(
      await evalRoute(`${targetOrigin}/admin/delete-all`, 'GET'),
      { aborted: true, continued: false },
      'Denylisted route MUST be aborted by forwarded ScopePolicy',
    )
    // Non-GET/HEAD target mutation is aborted
    assert.deepEqual(
      await evalRoute(`${targetOrigin}/api/users`, 'POST'),
      { aborted: true, continued: false },
      'Non-GET request to target origin MUST be aborted in unattended refresher',
    )
    assert.deepEqual(
      await evalRoute(`${targetOrigin}/api/items/42`, 'DELETE'),
      { aborted: true, continued: false },
    )
    // Allowed target GET and approved IdP POST continue cleanly
    assert.deepEqual(await evalRoute(`${targetOrigin}/api/me`, 'GET'), { aborted: false, continued: true })
    assert.deepEqual(await evalRoute(`${idpOrigin}/oauth/token`, 'POST'), { aborted: false, continued: true })

    // 2. Simulate the active run recording a write exchange (POST /dashboard?tab=1) in broker_exchanges
    const assignmentId = randomUUID()
    store.db.insert(assignments).values({
      id: assignmentId,
      runId: run.id,
      phase: 'investigation',
      status: 'running',
      scopeRevision: run.scopeRevision,
      goalRevision: run.goalRevision,
      sessionId: 'sess-r4-h3',
      attempt: 1,
      maxTurns: 10,
      turnsUsed: 1,
      requestsUsed: 1,
      parentFactIds: [],
      sourceOrigins: [targetOrigin],
      title: 'Test write exchange',
      objective: 'Test',
      createdAt: Date.now(),
    }).run()

    store.db.insert(brokerExchanges).values({
      id: randomUUID(),
      runId: run.id,
      assignmentId,
      scopeRevision: run.scopeRevision,
      origin: targetOrigin,
      finalOrigin: targetOrigin,
      redirectOrigins: [],
      method: 'POST',
      pathAndQuery: '/dashboard?tab=1',
      personaHandle: 'alice-browser',
      status: 201,
      mediaType: 'application/json',
      reqHeaders: {},
      respHeaders: {},
      bodyPreview: '{"ok":true}',
      bodySha256: '0'.repeat(64),
      secretMatches: [],
      durationMs: 12,
      createdAt: Date.now(),
    }).run()

    // 3. Subsequent refresh (both via authRes.refresh() and fresh authenticatePersona without explicit runId)
    //    MUST raise BrowserSessionRefreshBlockedError WITHOUT launching Chromium!
    const launchesBeforeMutationBlock = stubCapture.launchCount
    await assert.rejects(
      () => authRes.refresh!(),
      err => err instanceof BrowserSessionRefreshBlockedError && err.code === 'VERIFY_PATH_MODIFIED',
    )
    await assert.rejects(
      () => authManager.authenticatePersona(store, project.id, persona.id),
      err => err instanceof BrowserSessionRefreshBlockedError && err.code === 'VERIFY_PATH_MODIFIED',
    )
    assert.equal(
      stubCapture.launchCount,
      launchesBeforeMutationBlock,
      'Chromium MUST NOT launch once broker write exchanges mutate verifyPath',
    )
  })
})
