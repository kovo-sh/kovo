import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { createKovoLocalServer } from '../scripts/serve.ts'
import { parseCurlOrHeader, tokenizeShellArgs } from '../src/components/curl-parser.ts'
import {
  addCandidate,
  DEFAULT_PROVIDER,
  importProjectSpec,
  maxDnsExportBytes,
} from '../src/domain.ts'
import { parseDnsInventory } from '../src/passive-dns.ts'
import { RequestBroker } from '../src/server/broker.ts'
import {
  checkModelConnection,
  listModelProfiles,
  privateModelProfiles,
  recordProfileFailure,
  saveModelProfile,
} from '../src/server/model-settings.ts'
import {
  extractSupabaseConfigFromText,
  isSupabaseCredentialHost,
  PersonaAuthError,
  PersonaAuthManager,
} from '../src/server/persona-auth.ts'
import { buildPersonaHeader, createProjectPersona, resolveRunPersonas } from '../src/server/persona-vault.ts'
import { Store } from '../src/server/store.ts'
import { resolvePrimaryLabRepoDir, testPersonaAuth } from '../src/server/worker-session-reader.ts'

function makeFakeJwt(payload: Record<string, unknown>, sig = 'sig_test_9876543210'): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
  return `${header}.${body}.${sig}`
}

async function availablePort(): Promise<number> {
  const probe = createNetServer().listen(0, '127.0.0.1')
  await once(probe, 'listening')
  const addr = probe.address()
  if (!addr || typeof addr === 'string') throw new Error('Could not allocate port.')
  await new Promise<void>(resolve => probe.close(() => resolve()))
  return addr.port
}

async function startMockResponsesProvider() {
  let requests = 0
  const server = createServer((req, res) => {
    requests += 1
    req.resume()
    res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8' })
    const toolCallEvent = {
      type: 'response.output_item.done',
      item: {
        type: 'function_call',
        call_id: 'call_check_1',
        name: 'kovo_connection',
        arguments: JSON.stringify({ status: 'ready' }),
      },
    }
    const completedEvent = {
      type: 'response.completed',
      response: {
        id: 'resp_1',
        status: 'completed',
        output: [toolCallEvent.item],
        usage: { input_tokens: 10, output_tokens: 5 },
      },
    }
    res.write(`data: ${JSON.stringify(toolCallEvent)}\n\n`)
    res.write(`data: ${JSON.stringify(completedEvent)}\n\n`)
    res.end()
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address()
  if (!addr || typeof addr === 'string') throw new Error('Failed to bind mock provider')
  return {
    endpoint: `http://127.0.0.1:${addr.port}`,
    requests: () => requests,
    close: async () => { await new Promise<void>(resolve => server.close(() => resolve())) },
  }
}

// ---------------------------------------------------------------------------
// Wave A7: Model profiles create-collision & Test clearing circuit breaker
// ---------------------------------------------------------------------------

test('A7: creating a second OpenRouter profile without id never overwrites or unlinks the first profile key, and Test clears open cooldown', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-a7-models-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const provider = await startMockResponsesProvider()
  t.after(() => provider.close())

  const key1 = 'sk-or-v1-first-profile-secret-111111'
  const key2 = 'sk-or-v1-second-profile-secret-222222'

  const first = await saveModelProfile({
    name: DEFAULT_PROVIDER.name,
    endpoint: provider.endpoint,
    model: DEFAULT_PROVIDER.model,
    protocol: 'responses',
    key: key1,
    priority: 100,
  }, storage, { skipConnectionCheck: true })

  // Second profile omits `id` and sends the exact same default name — must NOT match or overwrite first!
  const second = await saveModelProfile({
    name: DEFAULT_PROVIDER.name,
    endpoint: provider.endpoint,
    model: 'anthropic/claude-sonnet-4.5',
    protocol: 'responses',
    key: key2,
    priority: 90,
  }, storage, { skipConnectionCheck: true })

  assert.notEqual(second.id, first.id, 'Second profile must receive a distinct id')

  const publicProfiles = listModelProfiles(storage)
  assert.equal(publicProfiles.length, 2)
  assert.equal(publicProfiles.find(p => p.id === first.id)?.name, DEFAULT_PROVIDER.name)
  assert.equal(publicProfiles.find(p => p.id === second.id)?.name, `${DEFAULT_PROVIDER.name} (2)`)

  // Both API keys must still exist on disk and resolve independently
  const privateProfiles = privateModelProfiles(storage)
  assert.equal(privateProfiles.length, 2)
  assert.equal(privateProfiles.find(p => p.id === first.id)?.key, key1)
  assert.equal(privateProfiles.find(p => p.id === second.id)?.key, key2)

  // Trip the first profile's circuit breaker (hard failure -> open + cooldownUntil + lastError)
  recordProfileFailure(first.id, 'HTTP 429 quota exceeded', true, storage)
  const tripped = listModelProfiles(storage).find(p => p.id === first.id)!
  assert.equal(tripped.healthState, 'open')
  assert.ok(tripped.cooldownUntil !== null && tripped.cooldownUntil > Date.now())
  assert.match(tripped.lastError ?? '', /429/)

  // Settings row Test (`checkModelConnection` with matching id + stored connection, blank key) clears cooldown immediately!
  const checked = await checkModelConnection({
    id: first.id,
    name: tripped.name,
    endpoint: tripped.endpoint,
    model: tripped.model,
    protocol: tripped.protocol,
    key: '',
    priority: tripped.priority,
    enabled: tripped.enabled,
  }, storage)
  assert.deepEqual(checked, { ok: true })
  assert.equal(provider.requests(), 1)

  const recovered = listModelProfiles(storage).find(p => p.id === first.id)!
  assert.equal(recovered.healthState, 'closed')
  assert.equal(recovered.cooldownUntil, null)
  assert.equal(recovered.lastError, null)

  // Negative check: testing an unsaved DIFFERENT model ID on a tripped profile must NOT clear the stored profile's cooldown
  recordProfileFailure(second.id, 'HTTP 503 upstream outage', true, storage)
  await checkModelConnection({
    id: second.id,
    name: `${DEFAULT_PROVIDER.name} (2)`,
    endpoint: provider.endpoint,
    model: 'different/unsaved-model',
    protocol: 'responses',
    key: '',
    priority: 90,
    enabled: true,
  }, storage)
  const stillTripped = listModelProfiles(storage).find(p => p.id === second.id)!
  assert.equal(stillTripped.healthState, 'open')
})

// ---------------------------------------------------------------------------
// Wave A9a: Supabase Auth apikey header, HTML/JS auto-extraction, host rules
// ---------------------------------------------------------------------------

test('A9a: Supabase adapter auto-extracts URL + anon key from target JS bundle, sends apikey on login & refresh, and enforces credential-host rules', async t => {
  const targetOrigin = 'https://app.northstar.example'
  const supabaseOrigin = 'https://projref1234.supabase.co'
  const anonKey = makeFakeJwt({ iss: 'supabase', ref: 'projref1234', role: 'anon', iat: 1_700_000_000 }, 'anon_pub_key_sig')
  const access1 = makeFakeJwt({ sub: 'supa_u1', exp: Math.floor(Date.now() / 1000) + 600 }, 'supa_acc_1')
  const access2 = makeFakeJwt({ sub: 'supa_u1', exp: Math.floor(Date.now() / 1000) + 1200 }, 'supa_acc_2')
  const refresh1 = 'supa_refresh_token_one_secret'
  const refresh2 = 'supa_refresh_token_two_secret'

  // R2-H-3: Discovered *.supabase.co origins are NEVER self-authorizing; require explicit allowlist or operator loginUrl
  assert.equal(isSupabaseCredentialHost(supabaseOrigin, [targetOrigin], undefined, supabaseOrigin), false)
  assert.equal(isSupabaseCredentialHost(supabaseOrigin, [targetOrigin, supabaseOrigin]), true)
  assert.equal(isSupabaseCredentialHost(supabaseOrigin, [targetOrigin], supabaseOrigin), true)
  assert.equal(isSupabaseCredentialHost('https://evil.example', [targetOrigin], undefined, 'https://evil.example'), false)

  // Verify service_role JWTs are never adopted as anon keys
  const serviceRoleJwt = makeFakeJwt({ iss: 'supabase', ref: 'projref1234', role: 'service_role' }, 'svc_sig')
  const extractedBad = extractSupabaseConfigFromText(`const k = "${serviceRoleJwt}";`, [targetOrigin, supabaseOrigin])
  assert.equal(extractedBad.supabaseAnonKey, null)

  const dir = mkdtempSync(join(tmpdir(), 'kovo-a9a-supabase-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'Supabase Auto-Extract Project',
    seeds: [targetOrigin],
    environment: 'public',
  })

  // Unapproved HTML/JS-discovered Supabase origin must be refused when absent from originAllowlist and loginUrl
  const unapprovedPersona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'supa_unapproved',
    roleLabel: 'Supabase Unapproved',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: {
      adapter: 'auto',
      email: 'alice@northstar.example',
    },
    secret: 'SupaStrongPass!9',
    canaryMarkers: [],
  })

  // Operator-allowlisted Supabase origin permits JS-bundle anon key extraction and login/refresh
  const persona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'supa_auto',
    roleLabel: 'Supabase Member',
    originAllowlist: [targetOrigin, supabaseOrigin],
    authKind: 'login',
    loginConfig: {
      adapter: 'auto',
      email: 'alice@northstar.example',
    },
    secret: 'SupaStrongPass!9',
    canaryMarkers: [],
  })

  const seenRequests: Array<{ url: string; method: string; apikey: string | null }> = []
  const manager = new PersonaAuthManager({
    resolveHost: async () => ['93.184.216.34'],
    fetchImpl: async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      const headers = new Headers(init?.headers)
      seenRequests.push({ url, method: init?.method ?? 'GET', apikey: headers.get('apikey') })

      if (url === targetOrigin) {
        return new Response(
          '<!doctype html><html><head><script src="/assets/app.js"></script></head><body><div id="root"></div></body></html>',
          { status: 200, headers: { 'content-type': 'text/html' } },
        )
      }
      if (url === `${targetOrigin}/assets/app.js`) {
        return new Response(
          `window.__ENV={NEXT_PUBLIC_SUPABASE_URL:"${supabaseOrigin}",NEXT_PUBLIC_SUPABASE_ANON_KEY:"${anonKey}"};`,
          { status: 200, headers: { 'content-type': 'application/javascript' } },
        )
      }
      if (url === `${supabaseOrigin}/auth/v1/token?grant_type=password`) {
        if (headers.get('apikey') !== anonKey) {
          return new Response(JSON.stringify({ msg: 'No API key found in request' }), { status: 401 })
        }
        return new Response(JSON.stringify({
          access_token: access1,
          refresh_token: refresh1,
          expires_in: 600,
        }), { status: 200, headers: { 'content-type': 'application/json' } })
      }
      if (url === `${supabaseOrigin}/auth/v1/token?grant_type=refresh_token`) {
        if (headers.get('apikey') !== anonKey) {
          return new Response(JSON.stringify({ msg: 'No API key found in request' }), { status: 401 })
        }
        return new Response(JSON.stringify({
          access_token: access2,
          refresh_token: refresh2,
          expires_in: 600,
        }), { status: 200, headers: { 'content-type': 'application/json' } })
      }
      return new Response('not found', { status: 404 })
    },
  })
  t.after(() => manager.stopAll())

  await assert.rejects(
    manager.authenticatePersona(storage, projectId, unapprovedPersona.id),
    /login|Supabase|URL|form|JSON/i,
  )
  assert.equal(
    seenRequests.some(r => r.url.startsWith(supabaseOrigin)),
    false,
    'R2-H-3: unapproved HTML/JS Supabase origin must never receive credentials',
  )

  const authRes = await manager.authenticatePersona(storage, projectId, persona.id)
  assert.equal(authRes.adapterUsed, 'supabase')
  assert.equal(authRes.headerType, 'bearer')
  assert.ok(typeof authRes.refresh === 'function')

  const loginReq = seenRequests.find(r => r.url.includes('grant_type=password'))
  assert.ok(loginReq)
  assert.equal(loginReq.apikey, anonKey)

  await authRes.refresh!()
  const refreshReq = seenRequests.find(r => r.url.includes('grant_type=refresh_token'))
  assert.ok(refreshReq)
  assert.equal(refreshReq.apikey, anonKey)

  const resolved = resolveRunPersonas(storage, projectId, [persona.id])
  assert.deepEqual(
    buildPersonaHeader(resolved.get('supa_auto')!, targetOrigin),
    { Authorization: `Bearer ${access2}` },
  )

  // Explicit operator apikey + custom header works without HTML discovery
  const explicitKey = 'sb_publishable_ExplicitOperatorKey_1234567890'
  const explicitPersona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'supa_explicit',
    roleLabel: 'Supabase Explicit',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: {
      adapter: 'supabase',
      email: 'bob@northstar.example',
      loginUrl: 'https://explicitref99.supabase.co',
      apikey: explicitKey,
      headers: { 'X-Client-Info': 'kovo-test' },
    },
    secret: 'BobPass!99',
    canaryMarkers: [],
  })

  let sawCustomHeader: string | null = null
  let sawExplicitKey: string | null = null
  const explicitMgr = new PersonaAuthManager({
    resolveHost: async () => ['93.184.216.34'],
    fetchImpl: async (input, init) => {
      const url = typeof input === 'string' ? input : input.toString()
      const h = new Headers(init?.headers)
      assert.equal(url, 'https://explicitref99.supabase.co/auth/v1/token?grant_type=password')
      sawExplicitKey = h.get('apikey')
      sawCustomHeader = h.get('x-client-info')
      return new Response(JSON.stringify({ access_token: access1, expires_in: 600 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    },
  })
  t.after(() => explicitMgr.stopAll())

  const resExplicit = await explicitMgr.authenticatePersona(storage, projectId, explicitPersona.id)
  assert.equal(resExplicit.adapterUsed, 'supabase')
  assert.equal(sawExplicitKey, explicitKey)
  assert.equal(sawCustomHeader, 'kovo-test')

  // Reject non-Supabase cross-origin loginUrl outside allowlist
  const evilPersona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'supa_evil',
    roleLabel: 'Evil Host',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: {
      adapter: 'supabase',
      email: 'bob@northstar.example',
      loginUrl: 'https://evil.example/auth/v1/token?grant_type=password',
      apikey: explicitKey,
    },
    secret: 'BobPass!99',
    canaryMarkers: [],
  })
  await assert.rejects(
    explicitMgr.authenticatePersona(storage, projectId, evilPersona.id),
    err => err instanceof PersonaAuthError && err.code === 'AUTH_FAILED' && /outside the persona origin allowlist/i.test(err.message),
  )
})

// ---------------------------------------------------------------------------
// Wave A9b: Shell-argument tokenizer & Chrome/Firefox DevTools cURL parser
// ---------------------------------------------------------------------------

test('A9b: cURL tokenizer handles Chrome/Firefox DevTools copy-as-cURL, $ quotes, line continuations, and skips sec-* noise headers', () => {
  // 1. Tokenizer edge cases: $'...', adjacent single quotes, backslash continuations
  const toks = tokenizeShellArgs(`curl 'https://app.example.com/me' \\\n  -H $'Cookie: a=1; b=it\\'s\\x3dok' \\\n  --header="X-Test: foo\\"bar"`)
  assert.deepEqual(toks, [
    'curl',
    'https://app.example.com/me',
    '-H',
    "Cookie: a=1; b=it's=ok",
    '--header=X-Test: foo"bar',
  ])

  // 2. Chrome DevTools "Copy as cURL (bash)" with -b and sec-ch-ua noise
  const chromeCurl = `curl 'https://portal.example.com/api/v1/profile' \\
  -H 'accept: */*' \\
  -H 'accept-language: en-US,en;q=0.9' \\
  -b '__session=eyJ123.abc.def; __client_uat=1715000000' \\
  -H 'origin: https://portal.example.com' \\
  -H 'priority: u=1, i' \\
  -H 'referer: https://other.example.com/login' \\
  -H 'sec-ch-ua: "Chromium";v="124"' \\
  -H 'sec-fetch-mode: cors' \\
  -H 'user-agent: Mozilla/5.0'`
  const parsedChrome = parseCurlOrHeader(chromeCurl)
  assert.ok(parsedChrome)
  assert.equal(parsedChrome.origin, 'https://portal.example.com')
  assert.equal(parsedChrome.authKind, 'cookie')
  assert.equal(parsedChrome.secret, '__session=eyJ123.abc.def; __client_uat=1715000000')

  // 3. Chrome DevTools with $'...' ANSI-C cookie containing escaped single quotes
  const ansiCurl = `curl 'https://shop.example.com/orders' \\\n  -b $'sid=tok\\'123; theme=dark'`
  const parsedAnsi = parseCurlOrHeader(ansiCurl)
  assert.ok(parsedAnsi)
  assert.equal(parsedAnsi.authKind, 'cookie')
  assert.equal(parsedAnsi.secret, "sid=tok'123; theme=dark")

  // 4. Firefox DevTools "Copy as cURL" with custom X-Api-Key buried after browser headers
  const firefoxCurl = `curl 'https://api.example.com/v2/items' \\
  -H 'User-Agent: Mozilla/5.0' \\
  -H 'Accept: application/json' \\
  -H 'Accept-Encoding: gzip, deflate, br' \\
  -H 'Sec-Fetch-Dest: empty' \\
  -H 'Sec-Fetch-Mode: cors' \\
  -H 'Sec-Fetch-Site: same-origin' \\
  -H 'X-Api-Key: kovo_live_secret_998877' \\
  --compressed`
  const parsedFirefox = parseCurlOrHeader(firefoxCurl)
  assert.ok(parsedFirefox)
  assert.equal(parsedFirefox.origin, 'https://api.example.com')
  assert.equal(parsedFirefox.authKind, 'header')
  assert.equal(parsedFirefox.headerName, 'X-Api-Key')
  assert.equal(parsedFirefox.secret, 'kovo_live_secret_998877')

  // 5. Chrome DevTools Bearer token with --header= syntax and Windows cmd ^ continuations
  const cmdCurl = `curl "https://api.example.com/graphql" ^\r\n  --header="Authorization: Bearer eyJtoken.part2.part3" ^\r\n  -H "sec-ch-ua: ^"Chromium^";v=^"124^""`
  const parsedCmd = parseCurlOrHeader(cmdCurl)
  assert.ok(parsedCmd)
  assert.equal(parsedCmd.origin, 'https://api.example.com')
  assert.equal(parsedCmd.authKind, 'bearer')
  assert.equal(parsedCmd.secret, 'eyJtoken.part2.part3')

  // 6. Multiple -b / Cookie flags merge cleanly, and -b /path/to/jar.txt (no '=') is ignored
  const multiCookie = parseCurlOrHeader(`curl --url https://app.example.com/ -b /tmp/cookies.txt -b 'a=1' --cookie='b=2'`)
  assert.ok(multiCookie)
  assert.equal(multiCookie.authKind, 'cookie')
  assert.equal(multiCookie.secret, 'a=1; b=2')
  assert.equal(multiCookie.origin, 'https://app.example.com')
})

// ---------------------------------------------------------------------------
// Wave A9d: Local-lab transport schemas & resolvePrimaryLabRepoDir + IAST wiring
// ---------------------------------------------------------------------------

test('A9d: addCandidate & importProjectSpec accept localhost under KOVO_ALLOW_LOCAL_LAB=1 while public projects stay strict, and resolvePrimaryLabRepoDir resolves <projectId>/<owner>/<repo>', t => {
  const prev = process.env.KOVO_ALLOW_LOCAL_LAB
  t.after(() => {
    if (prev === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prev
  })

  // Without KOVO_ALLOW_LOCAL_LAB=1, localhost is rejected at transport schema layer
  delete process.env.KOVO_ALLOW_LOCAL_LAB
  assert.equal(addCandidate.safeParse({ origin: 'http://localhost:3000', source: 'manual', thirdParty: false }).success, false)
  assert.equal(importProjectSpec.safeParse({
    requestId: randomUUID(),
    projectId: randomUUID(),
    name: 'OpenAPI',
    kind: 'openapi',
    origin: 'http://localhost:3000',
    content: 'openapi: 3.0.0',
  }).success, false)

  // With KOVO_ALLOW_LOCAL_LAB=1, transport schemas accept localhost
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  const cand = addCandidate.parse({ origin: 'http://localhost:3000', source: 'manual', thirdParty: false })
  assert.equal(cand.origin, 'http://localhost:3000')
  const spec = importProjectSpec.parse({
    requestId: randomUUID(),
    projectId: randomUUID(),
    name: 'Local API',
    kind: 'openapi',
    origin: 'http://localhost:3000',
    content: 'openapi: 3.0.0',
  })
  assert.equal(spec.origin, 'http://localhost:3000')

  // Store remains authoritative: public projects STILL reject localhost while local-lab accepts it
  const dir = mkdtempSync(join(tmpdir(), 'kovo-a9d-store-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const pubProj = storage.createProject({
    requestId: randomUUID(),
    name: 'Public Proj',
    seeds: ['https://app.example.com'],
    environment: 'public',
  })
  const labProj = storage.createProject({
    requestId: randomUUID(),
    name: 'Lab Proj',
    seeds: ['http://localhost:3000'],
    environment: 'local-lab',
  })

  assert.throws(() => storage.addProjectAsset({
    requestId: randomUUID(),
    projectId: pubProj.id,
    origin: 'http://localhost:3000',
    source: 'manual',
    thirdParty: false,
  }))
  const addedLab = storage.addProjectAsset({
    requestId: randomUUID(),
    projectId: labProj.id,
    origin: 'http://localhost:3001',
    source: 'manual',
    thirdParty: false,
  })
  assert.ok(addedLab.id)

  // resolvePrimaryLabRepoDir resolves <dataDir>/repos/<projectId>/<owner>/<repo>
  const baseRepoDir = join(dir, 'repos', labProj.id)
  assert.equal(resolvePrimaryLabRepoDir(dir, labProj.id), baseRepoDir)

  const repoA = join(baseRepoDir, 'acme', 'api-service')
  const repoB = join(baseRepoDir, 'acme', 'web-frontend')
  mkdirSync(repoA, { recursive: true })
  mkdirSync(repoB, { recursive: true })

  assert.equal(resolvePrimaryLabRepoDir(dir, labProj.id), repoA)
  assert.equal(resolvePrimaryLabRepoDir(dir, labProj.id, 'acme/web-frontend'), repoB)
  assert.equal(resolvePrimaryLabRepoDir(dir, labProj.id, 'web-frontend'), repoB)

  // Confirm actions.ts startRunLabAction uses resolvePrimaryLabRepoDir & passes telemetryDir when iastEnabled
  const actionsSrc = readFileSync(join(process.cwd(), 'src/actions.ts'), 'utf8')
  assert.match(actionsSrc, /resolvePrimaryLabRepoDir\(db\.directory,\s*project\.id,\s*project\.labConfig\.repo\)/)
  assert.match(actionsSrc, /project\.labConfig\.iastEnabled[\s\S]*telemetryDir:\s*join\(db\.directory,\s*'evidence',\s*'lab-telemetry'\)/)
})

// ---------------------------------------------------------------------------
// Wave C: serve.ts bootstrap-url cleanup + /_kovo/auth/status, Verify sign-in, DNS limit
// ---------------------------------------------------------------------------

test('C1: serve.ts deletes bootstrap-url on bootstrap & rotate-session and serves GET /_kovo/auth/status', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-c-serve-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const port = await availablePort()
  const publicOrigin = 'https://kovo.proxy.example'
  const local = createKovoLocalServer({
    app: { fetch: async () => new Response('ok') },
    directory: dir,
    port,
    publicOrigin,
  })
  local.server.listen(port, '127.0.0.1')
  await once(local.server, 'listening')
  t.after(async () => {
    local.server.closeAllConnections()
    await new Promise<void>(resolve => local.server.close(() => resolve()))
  })

  const origin = `http://127.0.0.1:${port}`
  const bootstrapUrlFile = join(dir, 'bootstrap-url')
  writeFileSync(bootstrapUrlFile, `${local.bootstrapUrl(origin)}\n`, { mode: 0o600 })
  assert.equal(existsSync(bootstrapUrlFile), true)

  // Unauthenticated GET /_kovo/auth/status -> 401
  const unauthStatus = await fetch(`${origin}/_kovo/auth/status`)
  assert.equal(unauthStatus.status, 401)

  // Consuming bootstrap deletes BOTH bootstrap and bootstrap-url
  const boot = await fetch(`${origin}/?bootstrap=${local.bootstrapSecret}`, { redirect: 'manual' })
  assert.equal(boot.status, 303)
  const cookie = (boot.headers.get('set-cookie') ?? '').split(';')[0]
  assert.equal(existsSync(join(dir, 'bootstrap')), false)
  assert.equal(existsSync(bootstrapUrlFile), false, 'bootstrap-url must be deleted on bootstrap consumption')

  // Authenticated GET /_kovo/auth/status on loopback reports loopbackOnly: true
  const statusRes = await fetch(`${origin}/_kovo/auth/status`, { headers: { Cookie: cookie } })
  assert.equal(statusRes.status, 200)
  const statusBody = await statusRes.json() as {
    authenticated: boolean
    origin: string
    loopbackOnly: boolean
    publicOriginConfigured: boolean
    activePairingLinks: number
  }
  assert.equal(statusBody.authenticated, true)
  assert.equal(statusBody.origin, origin)
  assert.equal(statusBody.loopbackOnly, true)
  assert.equal(statusBody.publicOriginConfigured, true)
  assert.equal(statusBody.activePairingLinks, 0)

  // Authenticated GET /_kovo/auth/status via HTTPS publicOrigin reports loopbackOnly: false
  const proxyStatus = await new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = httpRequest(
      { host: '127.0.0.1', port, method: 'GET', path: '/_kovo/auth/status', headers: { Host: 'kovo.proxy.example', Cookie: cookie } },
      res => {
        const chunks: Buffer[] = []
        res.on('data', c => chunks.push(Buffer.from(c)))
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }))
      },
    )
    req.on('error', reject)
    req.end()
  })
  assert.equal(proxyStatus.status, 200)
  const proxyParsed = JSON.parse(proxyStatus.body) as { loopbackOnly: boolean; origin: string }
  assert.equal(proxyParsed.loopbackOnly, false)
  assert.equal(proxyParsed.origin, publicOrigin)

  // Re-create bootstrap-url to verify rotate-session also deletes it and clears activePairingLinks
  writeFileSync(bootstrapUrlFile, 'stale-url\n', { mode: 0o600 })
  await fetch(`${origin}/_kovo/auth/pairing-link`, { method: 'POST', headers: { Origin: origin, Cookie: cookie } })
  const midStatus = await (await fetch(`${origin}/_kovo/auth/status`, { headers: { Cookie: cookie } })).json() as { activePairingLinks: number }
  assert.equal(midStatus.activePairingLinks, 1)

  const rot = await fetch(`${origin}/_kovo/auth/rotate-session`, { method: 'POST', headers: { Origin: origin, Cookie: cookie } })
  assert.equal(rot.status, 200)
  const newCookie = (rot.headers.get('set-cookie') ?? '').split(';')[0]
  assert.equal(existsSync(bootstrapUrlFile), false, 'bootstrap-url must be deleted on rotate-session')

  const afterRotStatus = await (await fetch(`${origin}/_kovo/auth/status`, { headers: { Cookie: newCookie } })).json() as { activePairingLinks: number }
  assert.equal(afterRotStatus.activePairingLinks, 0)

  // Confirm DevicesSessionModal queries /_kovo/auth/status and warns on loopback-only URLs
  const modalSrc = readFileSync(join(process.cwd(), 'src/components/settings/DevicesSessionModal.tsx'), 'utf8')
  assert.match(modalSrc, /\/_kovo\/auth\/status/)
  assert.match(modalSrc, /Loopback-only pairing URL/)
})

test('C2: testPersonaAuth flags identical 200 SPA shells as inconclusive and follows 1 same-origin 302 redirect', async t => {
  const prev = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  t.after(() => {
    if (prev === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prev
  })

  const server = createServer((req, res) => {
    const url = req.url ?? '/'
    const cookie = req.headers.cookie ?? ''
    const isAuthed = cookie.includes('sid=valid_session_99')

    // Case 1: Identical public SPA shell regardless of auth
    if (url === '/spa') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      res.end('<!doctype html><html><body><div id="app"></div><script src="/bundle.js"></script></body></html>')
      return
    }
    // Case 2: Same-origin redirect: authed -> /dashboard (200), anon -> /login (302)
    if (url === '/start') {
      res.writeHead(302, { location: isAuthed ? '/dashboard' : '/login' })
      res.end()
      return
    }
    if (url === '/dashboard') {
      if (!isAuthed) {
        res.writeHead(401, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'unauthorized' }))
        return
      }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      res.end('<html><body>Welcome Alice to your Dashboard</body></html>')
      return
    }
    // Case 3: Cross-origin redirect must NOT be followed
    if (url === '/sso') {
      res.writeHead(302, { location: 'https://idp.external.example/login' })
      res.end()
      return
    }
    res.writeHead(404)
    res.end('not found')
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(async () => { await new Promise<void>(resolve => server.close(() => resolve())) })
  const addr = server.address()
  assert.ok(addr && typeof addr !== 'string')
  const origin = `http://127.0.0.1:${addr.port}`

  const dir = mkdtempSync(join(tmpdir(), 'kovo-c-verify-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'Verify Sign-in Project',
    seeds: [origin],
    environment: 'local-lab',
  })
  const persona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'alice',
    roleLabel: 'Member',
    originAllowlist: [origin],
    authKind: 'cookie',
    secret: 'sid=valid_session_99',
    canaryMarkers: [],
  })

  const broker = new RequestBroker({
    resolve: async () => [{ address: '127.0.0.1', family: 4 }],
  })

  // 1. Identical 200 SPA shell -> inconclusive (NOT false-green!)
  const spaRes = await testPersonaAuth(storage, broker, { projectId, personaId: persona.id, origin, path: '/spa' })
  assert.equal(spaRes.ok, false)
  assert.equal(spaRes.inconclusive, true)
  assert.equal(spaRes.status, 200)
  assert.match(spaRes.authHint, /Inconclusive.*identical HTTP 200/i)

  // 2. Same-origin 302 -> /dashboard followed 1 hop and confirmed against anon 302 -> /login
  const dashRes = await testPersonaAuth(storage, broker, { projectId, personaId: persona.id, origin, path: '/start' })
  assert.equal(dashRes.ok, true)
  assert.equal(dashRes.status, 200)
  assert.equal(dashRes.path, '/dashboard')
  assert.match(dashRes.authHint, /redirect -> \/dashboard/)
  assert.match(dashRes.authHint, /diff vs anonymous/i)

  // 3. Cross-origin 302 is NOT followed
  const ssoRes = await testPersonaAuth(storage, broker, { projectId, personaId: persona.id, origin, path: '/sso' })
  assert.equal(ssoRes.ok, false)
  assert.equal(ssoRes.status, 302)
  assert.match(ssoRes.authHint, /redirect -> https:\/\/idp\.external\.example\/login/)
})

test('C3: DNS export size limit errors report 4 MiB (maxDnsExportBytes) and preview copy clarifies Needs approval', () => {
  // 200 KiB valid zone (> old 128 KiB text, < 4 MiB limit) succeeds
  const lines = ['$ORIGIN example.com.']
  for (let i = 0; i < 6_000; i += 1) {
    lines.push(`h${i} 300 IN A 93.184.216.34`)
  }
  const bigValid = lines.join('\n')
  assert.ok(Buffer.byteLength(bigValid) > 128 * 1024)
  assert.ok(Buffer.byteLength(bigValid) < maxDnsExportBytes)
  const parsed = parseDnsInventory('example.com', bigValid)
  assert.equal(parsed.candidates.length, 6_000)

  // > 4 MiB document fails with "4 MiB" (never "128 KiB")
  const oversized = 'a'.repeat(maxDnsExportBytes + 1)
  assert.throws(
    () => parseDnsInventory('example.com', oversized),
    err => err instanceof Error && /4 MiB/.test(err.message) && !/128 KiB/.test(err.message),
  )

  const uiSrc = readFileSync(join(process.cwd(), 'src/components/dns-inventory-import.tsx'), 'utf8')
  assert.ok(!uiSrc.includes('128 KiB'), 'dns-inventory-import.tsx must not reference stale 128 KiB limit')
  assert.match(uiSrc, /Needs approval/)
  assert.match(uiSrc, /all listed hosts/)
})
