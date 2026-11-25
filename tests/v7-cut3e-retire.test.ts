/**
 * Cut 3e: Retirement of legacy non-http_chain VMs from replay-verifier.ts.
 *
 * Verifies:
 *  1. Bare `browser_chain` fails closed (`retired_legacy_spec_kind`) with zero browser execution,
 *     while `browser_chain` carrying a `browser_sink` recipe envelope confirms via `ProofReceipt`.
 *  2. `rce_proof` runs zero-jq via `runRceProofRecipe` (Tier 3 + HITL gate, `dynamic_math`
 *     anti-reflection, `split_echo` concatenation guard, `oob_canary` ProofReceipt).
 *  3. `cache_differential` runs zero-jq via `runCacheDifferentialRecipe` (HIT vs MISS + unique _gcb).
 *  4. `auth_protocol_proof` runs via `runAuthProtocolProofRecipe` (OOB `jku_x5u_canary` ProofReceipt
 *     with zero jq, plus `alg_none` JWT differential).
 *  5. `static_ast_proof` runs zero-jq via `runStaticAstProofRecipe` and strictly preserves
 *     `static_verified` tier separation.
 */
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { RequestBroker } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { browserSinkEnvelopeFromSteps } from '../src/server/floor-recipes.ts'
import { RETIRED_LEGACY_SPEC_KINDS, RETIRED_LEGACY_SPEC_REASON, verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const origin = 'http://127.0.0.1:4392'

function baseSpec(overrides: Record<string, unknown>) {
  return {
    version: 1 as const,
    origin,
    title: 'Cut 3e typed runner test',
    category: 'security-check',
    cwe: 'CWE-284',
    severity: 'high' as const,
    severityRationale: 'Cut 3e verification fixture.',
    impact: 'Verifies typed runner parity after VM retirement.',
    remediation: 'Apply defense in depth.',
    recheckInstructions: 'Replay through typed runner.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
    ...overrides,
  }
}

function makeHs256Jwt(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url')
  const body = `${b64(header)}.${b64(payload)}`
  const sig = createHmac('sha256', 'cut3e-secret').update(body).digest('base64url')
  return `${body}.${sig}`
}

test('Cut 3e: bare browser_chain is retired while browser_sink recipe envelope confirms via ProofReceipt', async () => {
  assert.ok(RETIRED_LEGACY_SPEC_KINDS.has('browser_chain'))
  let browserCalls = 0
  const broker = new RequestBroker({ transport: async () => ({ status: 200, headers: {}, body: 'ok' }) })
  const fakeBrowser = {
    async runBrowserSession(steps: Array<{ role: string; canaryToken?: string }>) {
      browserCalls += 1
      const isProbe = steps.some(s => s.role === 'probe')
      return [{
        origin,
        finalUrl: `${origin}/vuln`,
        title: 'ok',
        status: 200,
        domSnippet: '',
        links: [],
        forms: [],
        xhrRequests: [],
        blockedOrigins: [],
        consoleMessages: [],
        postMessageListeners: { count: 0, hasOnMessage: false, handlers: [], observedEvents: 0, canaryHandledWithoutOriginCheck: false },
        cookieNames: [],
        localStorageKeys: [],
        sessionStorageKeys: [],
        canaryCheck: { token: steps[0]?.canaryToken ?? null, triggered: false, detail: null },
        domSinkTraces: isProbe ? [{ sink: 'innerHTML', preview: String(steps[0]?.canaryToken ?? ''), containsCanary: true, atMs: 1 }] : [],
        exchangeIds: [],
      }]
    },
  }
  const steps = [
    { id: 'c1', role: 'control' as const, description: 'safe', origin, pathAndQuery: '/safe', action: 'navigate' as const },
    { id: 'p1', role: 'probe' as const, description: 'vuln', origin, pathAndQuery: '/vuln?q={{canary_token}}', action: 'dom_xss_sink_hook' as const },
  ]
  const backend = new LinuxWorkerBackend()
  const grant = makeLabGrant(origin, { tier: 3, isStateChangeApproved: () => true })

  // 1. Bare browser_chain fails closed without touching browser
  const bare = await verifyReplaySpec({
    spec: baseSpec({ kind: 'browser_chain', steps }),
    broker,
    browser: fakeBrowser as never,
    backend,
    grant,
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(bare.verdict, 'dismissed')
  assert.equal(bare.outcome.reason, RETIRED_LEGACY_SPEC_REASON)
  assert.equal(browserCalls, 0)

  // 2. With browser_sink envelope, dom_xss_sink_hook on a new path maps to navigate and confirms via ProofReceipt
  const recipe = browserSinkEnvelopeFromSteps({ origin, vulnClass: 'dom_xss', steps })
  assert.ok(recipe)
  assert.deepEqual(recipe.args.steps?.map(s => [s.role, s.action, s.pathAndQuery]), [
    ['control', 'navigate', '/safe'],
    ['probe', 'navigate', '/vuln?q={{canary_token}}'],
  ])
  const enveloped = await verifyReplaySpec({
    spec: baseSpec({ kind: 'browser_chain', steps, recipe }),
    broker,
    browser: fakeBrowser as never,
    backend,
    grant,
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(enveloped.verdict, 'confirmed')
  assert.equal(enveloped.verificationTier, 'runtime_confirmed')
  assert.equal(enveloped.receipt?.verification.rule, 'browser')
  assert.equal(browserCalls, 2)
})

test('Cut 3e: rce_proof runs zero-jq with Tier-3/HITL gates, dynamic_math anti-reflection, split_echo guard, and OOB ProofReceipt', async () => {
  let evalMode: 'exec' | 'reflect' = 'exec'
  const broker = new RequestBroker({
    transport: async (_url, _addr, _sig, opts) => {
      const body = JSON.parse(opts?.body ?? '{}') as { expr?: string }
      const expr = body.expr ?? ''
      if (evalMode === 'exec') {
        const m = /^(\d+)\*(\d+)$/.exec(expr)
        if (m) return { status: 200, headers: { 'content-type': 'text/plain' }, body: `val=${Number(m[1]) * Number(m[2])}` }
      }
      return { status: 200, headers: { 'content-type': 'text/plain' }, body: `echo=${expr}` }
    },
  })
  // Backend throws if jq container is ever invoked, proving zero-jq execution.
  const noJqBackend = {
    ...new LinuxWorkerBackend(),
    async run() {
      throw new Error('Cut 3e zero-jq runner must not spawn jq')
    },
  }
  const spec = baseSpec({
    kind: 'rce_proof',
    cwe: 'CWE-1336',
    proofMode: 'dynamic_math',
    requiresTier3Approval: true,
    controlStep: { id: 'c', role: 'control', description: 'benign', request: { origin, method: 'POST', pathAndQuery: '/eval', jsonBody: { expr: 'hello' } } },
    probeStep: { id: 'p', role: 'probe', description: 'math', request: { origin, method: 'POST', pathAndQuery: '/eval', jsonBody: { expr: '{{nonce_a}}*{{nonce_b}}' } } },
  })

  const tier2 = await verifyReplaySpec({ spec, broker, backend: noJqBackend as never, grant: makeLabGrant(origin, { tier: 2 }), signal: AbortSignal.timeout(5_000) })
  assert.equal(tier2.verdict, 'inconclusive')
  assert.match(tier2.outcome.reason ?? '', /Tier 3/)

  const approvedGrant = makeLabGrant(origin, { tier: 3, isStateChangeApproved: () => true })
  const confirmed = await verifyReplaySpec({ spec, broker, backend: noJqBackend as never, grant: approvedGrant, signal: AbortSignal.timeout(5_000) })
  assert.equal(confirmed.verdict, 'confirmed')
  assert.equal(confirmed.verificationTier, 'runtime_confirmed')

  evalMode = 'reflect'
  const reflected = await verifyReplaySpec({ spec, broker, backend: noJqBackend as never, grant: approvedGrant, signal: AbortSignal.timeout(5_000) })
  assert.equal(reflected.verdict, 'dismissed')

  // OOB canary mode produces a strict ProofReceipt with zero jq
  const canaryBroker = new CanaryBroker()
  const oobBroker = new RequestBroker({
    transport: async (_url, _addr, _sig, opts) => {
      const parsed = JSON.parse(opts?.body ?? '{}') as { mode?: string; url?: string }
      if (parsed.mode === 'probe' && parsed.url) {
        void fetch(parsed.url, { signal: AbortSignal.timeout(3_000) }).catch(() => undefined)
      }
      return { status: 202, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
    },
  })
  try {
    const oobRes = await verifyReplaySpec({
      spec: baseSpec({
        kind: 'rce_proof',
        cwe: 'CWE-78',
        proofMode: 'oob_canary',
        requiresTier3Approval: true,
        controlStep: { id: 'c', role: 'control', description: 'ctrl', request: { origin, method: 'POST', pathAndQuery: '/job', jsonBody: { mode: 'ctrl', url: '{{canary_url}}' } } },
        probeStep: { id: 'p', role: 'probe', description: 'probe', request: { origin, method: 'POST', pathAndQuery: '/job', jsonBody: { mode: 'probe', url: '{{canary_url}}' } } },
      }),
      broker: oobBroker,
      canaryBroker,
      backend: noJqBackend as never,
      grant: approvedGrant,
      signal: AbortSignal.timeout(10_000),
    })
    assert.equal(oobRes.verdict, 'confirmed')
    assert.equal(oobRes.receipt?.verification.rule, 'oob')
    assert.equal(oobRes.receipt?.verification.confirmed, true)
  } finally {
    await canaryBroker.stop()
  }
})

test('Cut 3e: cache_differential and static_ast_proof run zero-jq with exact verdict semantics', async t => {
  const poisoned = new Map<string, string>()
  let serveHit = true
  const broker = new RequestBroker({
    transport: async (url, _addr, _sig, opts) => {
      const gcb = url.searchParams.get('_gcb') ?? ''
      const xfh = opts?.headers?.['X-Forwarded-Host'] ?? opts?.headers?.['x-forwarded-host']
      if (xfh && gcb) poisoned.set(gcb, xfh)
      if (poisoned.has(gcb) && serveHit) {
        return {
          status: 200,
          headers: { 'content-type': 'text/plain', 'x-cache': xfh ? 'MISS' : 'HIT', ...(xfh ? {} : { age: '9' }) },
          body: `HOST=${poisoned.get(gcb)}`,
        }
      }
      return { status: 200, headers: { 'content-type': 'text/plain', 'x-cache': 'MISS' }, body: 'HOST=clean' }
    },
  })
  const noJqBackend = {
    ...new LinuxWorkerBackend(),
    async run() {
      throw new Error('Cut 3e zero-jq runner must not spawn jq')
    },
  }
  const grant = makeLabGrant(origin, { tier: 2 })
  const cacheSpec = baseSpec({
    kind: 'cache_differential',
    cwe: 'CWE-444',
    targetOrigin: origin,
    controlPath: '/home?_gcb={{control_gcb}}',
    probePath: '/home?_gcb={{probe_gcb}}',
    poisonHeaders: { 'X-Forwarded-Host': 'poison.invalid' },
  })
  const hit = await verifyReplaySpec({ spec: cacheSpec, broker, backend: noJqBackend as never, grant, signal: AbortSignal.timeout(5_000) })
  assert.equal(hit.verdict, 'confirmed')
  assert.equal(hit.verificationTier, 'runtime_confirmed')

  serveHit = false
  const miss = await verifyReplaySpec({ spec: cacheSpec, broker, backend: noJqBackend as never, grant, signal: AbortSignal.timeout(5_000) })
  assert.equal(miss.verdict, 'dismissed')

  // static_ast_proof: strictly static_verified (never runtime_confirmed), zero jq
  const reposDir = mkdtempSync(join(tmpdir(), 'guardian-cut3e-ast-'))
  t.after(() => rmSync(reposDir, { recursive: true, force: true }))
  mkdirSync(join(reposDir, 'app'), { recursive: true })
  writeFileSync(join(reposDir, 'app', 'vuln.ts'), 'export function run(x: string) {\n  return eval(x)\n}\n', 'utf8')
  const astSpec = baseSpec({
    kind: 'static_ast_proof',
    cwe: 'CWE-95',
    repo: 'app',
    file: 'vuln.ts',
    startLine: 1,
    endLine: 3,
    engine: 'opengrep',
    ruleOrPattern: 'eval\\(',
    runtimeProofGap: 'Unit test static AST verification.',
  })
  const astBackend = {
    async run() {
      throw new Error('Cut 3e zero-jq runner must not spawn jq')
    },
    async verifyStaticAst(_aid: string, req: { ruleOrPattern: string }) {
      const hit = req.ruleOrPattern.includes('eval')
      return {
        verified: hit,
        matchCount: hit ? 1 : 0,
        matchedLines: hit ? ['2:  return eval(x)'] : [],
        ...(hit ? {} : { reason: 'pattern not found' }),
      }
    },
  }
  const astOk = await verifyReplaySpec({
    spec: astSpec,
    broker,
    backend: astBackend as never,
    reposDir,
    grant: makeLabGrant(origin, { tier: 0 }),
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(astOk.verdict, 'static_verified')
  assert.equal(astOk.verificationTier, 'static_verified')

  const astMiss = await verifyReplaySpec({
    spec: { ...astSpec, ruleOrPattern: 'nonexistent_sink_symbol' },
    broker,
    backend: astBackend as never,
    reposDir,
    grant: makeLabGrant(origin, { tier: 0 }),
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(astMiss.verdict, 'dismissed')
})

test('Cut 3e: auth_protocol_proof OOB jku_x5u_canary verifies via ProofReceipt with zero jq', async () => {
  const jwt = makeHs256Jwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'u1' })
  const canaryBroker = new CanaryBroker()
  await canaryBroker.startListener({ host: '127.0.0.1', port: 0 })
  const broker = new RequestBroker({
    transport: async (_url, _addr, _sig, opts) => {
      const auth = String(opts?.headers?.authorization ?? opts?.headers?.Authorization ?? '')
      if (auth.startsWith('Bearer ')) {
        const hdr = JSON.parse(Buffer.from(auth.slice(7).split('.')[0], 'base64url').toString('utf8')) as { jku?: string }
        if (hdr.jku) void fetch(hdr.jku, { signal: AbortSignal.timeout(3_000) }).catch(() => undefined)
      }
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
    },
  })
  const noJqBackend = {
    async run() {
      throw new Error('OOB auth_protocol_proof must verify via ProofReceipt without jq')
    },
  }
  const personas = new Map([[
    'jwt_u',
    {
      handle: 'jwt_u',
      roleLabel: 'User',
      authKind: 'bearer' as const,
      originAllowlist: [origin],
      secret: jwt,
      session: { headerName: 'Authorization', headerType: 'Bearer', value: jwt },
    },
  ]])
  try {
    const res = await verifyReplaySpec({
      spec: baseSpec({
        kind: 'auth_protocol_proof',
        protocol: 'jwt',
        cwe: 'CWE-347',
        category: 'broken-access-control',
        steps: [
          { id: 'c1', role: 'control', description: 'valid', request: { origin, method: 'GET', pathAndQuery: '/jku', persona: 'jwt_u' } },
          { id: 'p1', role: 'probe', description: 'jku canary', request: { origin, method: 'GET', pathAndQuery: '/jku', persona: 'jwt_u', authMutation: { kind: 'jku_x5u_canary', header: 'jku' } } },
        ],
      }),
      broker,
      canaryBroker,
      backend: noJqBackend as never,
      grant: makeLabGrant(origin, { tier: 2, personas: personas as never }),
      signal: AbortSignal.timeout(10_000),
    })
    assert.equal(res.verdict, 'confirmed')
    assert.equal(res.receipt?.verification.rule, 'oob')
    assert.equal(res.receipt?.verification.confirmed, true)
  } finally {
    await canaryBroker.stopListener()
    await canaryBroker.stop()
  }
})

test('Cut 3e (#181 P0 regression): authenticated reflected XSS confirms through browser_sink, produces schema-valid recordSpec, retests, and fails closed when patched', async t => {
  const { createServer } = await import('node:http')
  const { declarativeReplaySpecSchema } = await import('../src/replay-spec.ts')
  const { ScopedBrowser } = await import('../src/server/scoped-browser.ts')
  const { planFloorRecipe, recipeSpecRecord, retestPersistedRecipe, runPlannedRecipe } = await import('../src/server/floor-recipe-engine.ts')

  let patched = false
  const server = createServer((req, res) => {
    const u = new URL(req.url ?? '/', 'http://127.0.0.1')
    // Strictly authenticated route (like acme.reflected-search-xss / og.account-search-xss):
    // anonymous requests are denied with 401 and never render the reflected search page.
    if (req.headers.authorization !== 'Bearer auth-xss-token-001') {
      res.statusCode = 401
      res.setHeader('Content-Type', 'text/html')
      res.end('<html><body>Unauthorized</body></html>')
      return
    }
    const q = u.searchParams.get('q') ?? ''
    const rendered = patched
      ? q.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;')
      : q
    res.setHeader('Content-Type', 'text/html')
    res.end(`<html><head><title>Search</title></head><body><h1>Results</h1><div id="results">${rendered}</div></body></html>`)
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()))
  t.after(() => server.close())
  const addr = server.address() as { port: number }
  const appOrigin = `http://127.0.0.1:${addr.port}`

  const payload = `<img src=x onerror="document.title='{{canary_token}}'">`
  const encodedPayload = payload.split('{{canary_token}}').map(encodeURIComponent).join('{{canary_token}}')
  const candidateSteps = [
    { id: 'c1', role: 'control', description: 'Control benign search', origin: appOrigin, persona: 'member_a', pathAndQuery: '/search?q=guardian', action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 200 },
    { id: 'p1', role: 'probe', description: 'Probe reflected XSS', origin: appOrigin, persona: 'member_a', pathAndQuery: `/search?q=${encodedPayload}`, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 600 },
  ]
  const hypothesis = {
    intent: 'xss_reflected',
    probeClass: 'xss_context',
    method: 'GET',
    pathAndQuery: '/search?q=guardian',
    ownerPersona: 'member_a',
    endpoint: { origin: appOrigin, pathTemplate: '/search', method: 'GET' },
  }
  const plan = planFloorRecipe({
    hypothesis: hypothesis as never,
    probe: { verdict: 'signal', anomalies: [{ type: 'xss_context', context: 'html_body', unencodedChars: ['<', '"'] }] } as never,
    specKind: 'browser_chain',
    vulnClass: 'xss_reflected',
    personas: [],
    candidateSpec: { kind: 'browser_chain', steps: candidateSteps },
  })
  assert.ok(plan && !plan.skipReason, `expected browser_sink plan, got ${JSON.stringify(plan)}`)
  assert.equal(plan.recipeId, 'browser_sink')
  assert.equal(plan.vulnClass, 'xss_reflected')

  const personas = new Map([[
    'member_a',
    {
      handle: 'member_a',
      roleLabel: 'Member',
      authKind: 'bearer' as const,
      originAllowlist: [appOrigin],
      secret: 'auth-xss-token-001',
      session: { headerName: 'Authorization', headerType: 'Bearer', value: 'auth-xss-token-001' },
    },
  ]])
  const broker = new RequestBroker({ rejectUnauthorized: false })
  const browser = new ScopedBrowser(broker)
  const grant = makeLabGrant(appOrigin, { tier: 2, personas: personas as never })

  // 1. Vulnerable authenticated route confirms through runPlannedRecipe -> ProofReceipt (browser rule)
  const exec = await runPlannedRecipe({
    plan,
    hypothesis: hypothesis as never,
    broker,
    browser,
    grant,
    signal: AbortSignal.timeout(20_000),
  })
  assert.equal(exec.result.confirmed, true, `expected authenticated reflected XSS to confirm: ${exec.failure?.message ?? exec.result.verification.reason}`)
  assert.equal(exec.result.verification.rule, 'browser')

  // 2. Persisted record spec MUST pass declarativeReplaySpecSchema.safeParse (regression from 4375eb8!)
  const record = recipeSpecRecord(plan, exec)
  const parsed = declarativeReplaySpecSchema.safeParse(record.spec)
  assert.equal(parsed.success, true, parsed.success ? '' : `recordSpec schema failed: ${parsed.error.message}`)
  assert.equal(record.spec.cwe, 'CWE-79')

  // 3. Patched (HTML-escaped) route fails closed (100% precision)
  patched = true
  const fixedRetest = await retestPersistedRecipe({
    envelope: { recipeId: plan.recipeId, args: plan.args as unknown as Record<string, unknown> },
    specKind: 'browser_chain',
    vulnClass: 'xss_reflected',
    endpoint: '/search',
    origin: appOrigin,
    broker,
    grant,
    signal: AbortSignal.timeout(20_000),
    browserSession: (await import('../src/server/floor-recipe-engine.ts')).browserSessionSeam({
      browser,
      grant,
      signal: AbortSignal.timeout(20_000),
      origin: appOrigin,
    }),
  })
  assert.equal(fixedRetest.verdict, 'fixed')
})
