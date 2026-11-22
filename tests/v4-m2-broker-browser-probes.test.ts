import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHmac, generateKeyPairSync, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { promisify } from 'node:util'
import {
  browserChainReplaySpecSchema,
  declarativeReplaySpecSchema,
  replayStepSchema,
  sqlBooleanDiffReplaySpecSchema,
  sqlTimeDiffReplaySpecSchema,
} from '../src/replay-spec.ts'
import { differentialProbeClasses, probeParamLocations } from '../src/server/agent-session.ts'
import { BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { Grant, PublicAddress } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { createProjectPersona, resolveRunPersonas } from '../src/server/persona-vault.ts'
import { verifyReplaySpec, verifyReplaySpecInline } from '../src/server/replay-verifier.ts'
import { ScopedBrowser } from '../src/server/scoped-browser.ts'
import { assignments as assignmentsTable } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import { probeDifferential } from '../src/server/surface-engine.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'

const exec = promisify(execFile)
const publicAddr: PublicAddress = { address: '93.184.216.34', family: 4 }
const appOrigin = 'https://app.m2test.example'

async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T> | T): Promise<T> {
  const prev: Record<string, string | undefined> = {}
  for (const [k, v] of Object.entries(vars)) {
    prev[k] = process.env[k]
    if (v === undefined) delete process.env[k]
    else process.env[k] = v
  }
  try {
    return await fn()
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  }
}

async function httpFixture(
  handler: (req: IncomingMessage, body: string, res: ServerResponse) => void | Promise<void>,
  host = '127.0.0.1',
) {
  const requests: Array<{ method: string; url: string; headers: Record<string, string | string[] | undefined>; body: string }> = []
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(Buffer.from(c)))
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      requests.push({
        method: req.method ?? 'GET',
        url: req.url ?? '/',
        headers: req.headers,
        body,
      })
      void Promise.resolve(handler(req, body, res)).catch(err => {
        if (!res.headersSent) res.statusCode = 500
        res.end(String(err))
      })
    })
  }).listen(0, host)
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Fixture has no address.')
  const origin = `http://${host}:${address.port}`
  return {
    port: address.port,
    origin,
    requests,
    close() {
      server.closeAllConnections()
      return new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}

function makeTempStore(prefix = 'guardian-m2-') {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  const storage = new Store(dir)
  return {
    dir,
    storage,
    close() {
      storage.close()
      rmSync(dir, { recursive: true, force: true })
    },
  }
}

function setupApprovedRun(storage: Store, origin: string, environment: 'public' | 'local-lab' = 'local-lab') {
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: `M2 Project ${randomUUID().slice(0, 6)}`,
    seeds: [origin],
    environment,
  })
  const run = storage.createRun({
    requestId: randomUUID(),
    projectId,
    goal: 'M2 security test run',
    sourceMode: 'public',
    capabilityTier: 2,
    budgetUsd: 5,
    budgetRequests: 200,
    maxRpsPerOrigin: 30,
    workerConcurrency: 2,
    workerMaxTurns: 20,
  })
  const assignmentId = randomUUID()
  storage.client.prepare(
    `INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at)
     VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', ?, 'M2 Assignment', 'Verify M2 flows', ?)`,
  ).run(assignmentId, run.id, randomUUID(), JSON.stringify([origin]), Date.now())
  return { projectId, runId: run.id, assignmentId }
}

function makeLabGrant(origin: string, overrides: Partial<Grant> = {}): Grant {
  return {
    origin,
    tier: 2,
    allowLocalLab: true,
    maxRpsPerOrigin: 50,
    canRead: o => o === origin,
    audit: () => {},
    ...overrides,
  }
}

function makePublicGrant(origin: string, overrides: Partial<Grant> = {}): Grant {
  return {
    origin,
    tier: 2,
    allowLocalLab: false,
    maxRpsPerOrigin: 50,
    canRead: o => o === origin,
    audit: () => {},
    ...overrides,
  }
}

function makeSignedJwt(header: Record<string, unknown>, payload: Record<string, unknown>, secret = 'hs-secret-m2'): string {
  const h = Buffer.from(JSON.stringify(header)).toString('base64url')
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const s = createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url')
  return `${h}.${p}.${s}`
}

function createJqBackend(): WorkerBackend {
  return {
    async run(job, signal) {
      const dir = mkdtempSync(join(tmpdir(), 'guardian-m2-jq-'))
      try {
        for (const f of job.files) {
          writeFileSync(join(dir, f.name.replace(/\//g, '_')), f.content, 'utf8')
        }
        const match = /^jq\s+'([\s\S]*)'\s+\/evidence\/replay-results\.json\s+>\s+\/work\/outcome\.json$/.exec(job.command.trim())
        if (!match) {
          return { exitCode: 1, stdout: '', stderr: `Unsupported command: ${job.command}`, outputs: {} as Record<string, string> }
        }
        const jqFilter = match[1].replaceAll("'\\''", "'")
        const inputPath = join(dir, 'replay-results.json')
        try {
          const { stdout, stderr } = await exec('jq', [jqFilter, inputPath], { signal, timeout: job.timeoutMs ?? 15_000 })
          return { exitCode: 0, stdout, stderr, outputs: { 'outcome.json': stdout } as Record<string, string> }
        } catch (err) {
          const e = err as { code?: number; stdout?: string; stderr?: string; message?: string }
          return {
            exitCode: typeof e.code === 'number' ? e.code : 2,
            stdout: e.stdout ?? '',
            stderr: e.stderr ?? e.message ?? 'jq failed',
            outputs: {} as Record<string, string>,
          }
        }
      } finally {
        rmSync(dir, { recursive: true, force: true })
      }
    },
    async verifyStaticAst() {
      return {
        verified: false,
        engine: 'opengrep',
        repo: 'r',
        file: 'f',
        startLine: 1,
        endLine: 1,
        matchedLines: [],
        codeExcerpt: '',
        matchCount: 0,
        durationMs: 1,
      }
    },
    async openSession() {
      throw new Error('Not needed in M2 test.')
    },
  }
}

// ============================================================================
// M2.1: Session Jar Isolation, Bounds, Precedence & Scope Purge
// ============================================================================

test('M2.1 session jar isolation: regex BVA, LRU caps, origin/path/secure scoping, setup->probe vs control isolation, vault precedence, and scope purge', async t => {
  const secretCookie = 'M2_SECRET_SID_998877'
  const fx1 = await httpFixture((req, _b, res) => {
    const u = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (u.pathname === '/login') {
      res.setHeader('Set-Cookie', [
        `sid=${secretCookie}; HttpOnly; Path=/`,
        'admin_tok=ADM_123; Path=/admin; HttpOnly',
        'sec_only=SEC_456; Secure; Path=/',
      ])
      res.end('ok')
      return
    }
    if (u.pathname === '/bake-many') {
      res.setHeader('Set-Cookie', Array.from({ length: 40 }, (_, i) => `k${i}=v${i}; Path=/`))
      res.end('baked')
      return
    }
    if (u.pathname === '/vault-collision') {
      res.setHeader('Set-Cookie', ['vault_sid=ATTACKER_JAR; Path=/', 'extra_jar=EXTRA_VAL; Path=/'])
      res.end('ok')
      return
    }
    res.setHeader('Content-Type', 'application/json')
    const rawCookie = req.headers.cookie ?? ''
    res.end(JSON.stringify({
      hasSid: rawCookie.includes(secretCookie),
      hasAdmin: rawCookie.includes('ADM_123'),
      hasSec: rawCookie.includes('SEC_456'),
      hasVaultAuth: rawCookie.includes('VAULT_AUTHORITATIVE_777'),
      hasVaultOverwrite: rawCookie.includes('ATTACKER_JAR'),
      hasExtra: rawCookie.includes('EXTRA_VAL'),
      cookie: rawCookie,
    }))
  })
  t.after(() => fx1.close())

  const fx2 = await httpFixture((req, _b, res) => {
    res.setHeader('Content-Type', 'application/json')
    const rawCookie = req.headers.cookie ?? ''
    res.end(JSON.stringify({
      hasSid: rawCookie.includes(secretCookie),
      hasAdmin: rawCookie.includes('ADM_123'),
      hasSec: rawCookie.includes('SEC_456'),
      hasVaultAuth: rawCookie.includes('VAULT_AUTHORITATIVE_777'),
      hasVaultOverwrite: rawCookie.includes('ATTACKER_JAR'),
      hasExtra: rawCookie.includes('EXTRA_VAL'),
      cookie: rawCookie,
    }))
  })
  t.after(() => fx2.close())

  const tmp = makeTempStore()
  t.after(() => tmp.close())
  const broker = new RequestBroker({ rejectUnauthorized: false })
  const sig = AbortSignal.timeout(15_000)

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    const { projectId, runId, assignmentId } = setupApprovedRun(tmp.storage, fx1.origin)

    const { id: personaId } = createProjectPersona(tmp.storage, {
      requestId: randomUUID(),
      projectId,
      handle: 'vault_cookie',
      roleLabel: 'VaultUser',
      originAllowlist: [fx1.origin],
      authKind: 'cookie',
      secret: 'vault_sid=VAULT_AUTHORITATIVE_777',
      canaryMarkers: [],
    })
    const personas = resolveRunPersonas(tmp.storage, projectId, [personaId])
    let allowFx1 = true
    const grant = makeLabGrant(fx1.origin, {
      personas,
      canRead: o => (o === fx1.origin ? allowFx1 : o === fx2.origin),
    })
    // BVA on session handle
    for (const bad of ['', 'a'.repeat(33), '../x', 'BAD_UPPER', 'a b']) {
      await assert.rejects(
        broker.executeHttp({ origin: fx1.origin, method: 'GET', pathAndQuery: '/', session: bad }, grant, sig),
        BrokerDenied,
      )
    }
    for (const good of ['a', 'a_b-1'.padEnd(32, '0')]) {
      const ok = await broker.executeHttp({ origin: fx1.origin, method: 'GET', pathAndQuery: '/echo', session: good, runId, assignmentId }, grant, sig)
      assert.equal(ok.status, 200)
    }

    // Login sets cookies in jar-1; /admin/echo gets admin_tok, /public/echo does not, Secure is omitted over http
    await broker.executeHttp({ origin: fx1.origin, method: 'GET', pathAndQuery: '/login', session: 'jar-1', runId, assignmentId }, grant, sig)
    const adminEcho = JSON.parse((await broker.executeHttp({ origin: fx1.origin, method: 'GET', pathAndQuery: '/admin/echo', session: 'jar-1', runId, assignmentId }, grant, sig)).body)
    assert.equal(adminEcho.hasSid, true)
    assert.equal(adminEcho.hasAdmin, true)
    assert.equal(adminEcho.hasSec, false)
    assert.ok(!adminEcho.cookie.includes(secretCookie), 'Broker must scrub raw jar cookie from echoed response body')

    const pubEcho = JSON.parse((await broker.executeHttp({ origin: fx1.origin, method: 'GET', pathAndQuery: '/public/echo', session: 'jar-1', runId, assignmentId }, grant, sig)).body)
    assert.equal(pubEcho.hasAdmin, false)

    // Origin2 must never receive jar-1 cookies
    const fx2Echo = JSON.parse((await broker.executeHttp({ origin: fx2.origin, method: 'GET', pathAndQuery: '/echo', session: 'jar-1', runId, assignmentId }, grant, sig)).body)
    assert.equal(fx2Echo.cookie, '')

    // 40-cookie cap bounded <= 32
    await broker.executeHttp({ origin: fx1.origin, method: 'GET', pathAndQuery: '/bake-many', session: 'jar-cap', runId, assignmentId }, grant, sig)
    await broker.executeHttp({ origin: fx1.origin, method: 'GET', pathAndQuery: '/echo', session: 'jar-cap', runId, assignmentId }, grant, sig)
    const sentCookieHdr = String(fx1.requests.at(-1)?.headers.cookie ?? '')
    const count = sentCookieHdr.split(';').filter((s: string) => s.trim().length > 0).length
    assert.ok(count >= 1 && count <= 32, `Expected <= 32 cookies, got ${count}`)

    // Persona Vault precedence + zero leak in BrokerExchangeResult
    await broker.executeHttp({ origin: fx1.origin, method: 'GET', pathAndQuery: '/vault-collision', persona: 'vault_cookie', session: 'jar-vault', runId, assignmentId }, grant, sig)
    const vaultEx = await broker.executeHttp({ origin: fx1.origin, method: 'GET', pathAndQuery: '/echo', persona: 'vault_cookie', session: 'jar-vault', runId, assignmentId }, grant, sig)
    const vaultBody = JSON.parse(vaultEx.body)
    assert.equal(vaultBody.hasVaultAuth, true)
    assert.equal(vaultBody.hasVaultOverwrite, false)
    assert.equal(vaultBody.hasExtra, true)
    assert.ok(!JSON.stringify(vaultEx).includes('VAULT_AUTHORITATIVE_777'))
    assert.ok(!JSON.stringify(vaultEx).includes('EXTRA_VAL'))

    // ReplayVerifier http_chain: setup seeds probe, while control remains isolated from probe
    const chainRes = await verifyReplaySpec({
      spec: {
        version: 1,
        kind: 'http_chain',
        origin: fx1.origin,
        title: 'Session jar setup vs control vs probe isolation',
        category: 'broken-access-control',
        cwe: 'CWE-384',
        severity: 'medium',
        severityRationale: 'Verify setup->probe jar sharing and control isolation.',
        impact: 'Session isolation',
        remediation: 'Isolate sessions',
        recheckInstructions: 'Re-run',
        steps: [
          { id: 's1', role: 'setup', description: 'Setup login', request: { origin: fx1.origin, method: 'GET', pathAndQuery: '/login', session: 'shared-s' } },
          { id: 'c1', role: 'control', description: 'Control modifies its own jar via /vault-collision', request: { origin: fx1.origin, method: 'GET', pathAndQuery: '/vault-collision', session: 'shared-s' } },
          { id: 'p1', role: 'probe', description: 'Probe sees setup sid but NOT control EXTRA_VAL', request: { origin: fx1.origin, method: 'GET', pathAndQuery: '/echo', session: 'shared-s' } },
        ],
        assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.json.hasSid == true and .steps.p1.json.hasExtra == false), observed: "isolated", expected: "clean" }',
      } as unknown,
      broker,
      backend: createJqBackend(),
      grant,
      signal: AbortSignal.timeout(30_000),
    })
    assert.equal(chainRes.verdict, 'confirmed', JSON.stringify(chainRes.outcome))
    assert.ok(!JSON.stringify(chainRes).includes(secretCookie))

    // Scope revocation purges origin cookies immediately
    allowFx1 = false
    await assert.rejects(
      broker.executeHttp({ origin: fx1.origin, method: 'GET', pathAndQuery: '/echo', session: 'jar-1', runId, assignmentId }, grant, sig),
      BrokerDenied,
    )
    allowFx1 = true
    const afterRevoke = JSON.parse((await broker.executeHttp({ origin: fx1.origin, method: 'GET', pathAndQuery: '/echo', session: 'jar-1', runId, assignmentId }, grant, sig)).body)
    assert.equal(afterRevoke.hasSid, false)
  })
})

// ============================================================================
// M2.2: Automatic CSRF Extraction & Binding (csrfBind) + Rotation
// ============================================================================

test('M2.2 csrfBind: extracts XSRF cookie, meta, hidden input, JSON token; rotates; binds & redacts', async t => {
  let rot = 0
  const fx = await httpFixture((req, body, res) => {
    const u = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (u.pathname === '/cookie-init') {
      rot += 1
      res.setHeader('Set-Cookie', `XSRF-TOKEN=xsrf_rot_${rot}; Path=/`)
      res.end('ok')
      return
    }
    if (u.pathname === '/meta-init') {
      res.setHeader('Content-Type', 'text/html')
      res.end('<html><head><meta content="meta_tok_111" name="csrf-token"></head></html>')
      return
    }
    if (u.pathname === '/form-init') {
      res.setHeader('Content-Type', 'text/html')
      res.end('<form><input value="hidden_tok_222" name="__RequestVerificationToken" type="hidden"></form>')
      return
    }
    if (u.pathname === '/json-init') {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ csrfToken: 'json_tok_333' }))
      return
    }
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({
      xsrfHdr: req.headers['x-xsrf-token'] ?? null,
      csrfHdr: req.headers['x-csrf-token'] ?? null,
      body,
    }))
  })
  t.after(() => fx.close())

  const broker = new RequestBroker({ rejectUnauthorized: false })
  const grant = makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true })
  const sig = AbortSignal.timeout(15_000)

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    // Rotation on cookie XSRF-TOKEN -> binds X-XSRF-TOKEN with newest token
    await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/cookie-init', session: 'c-rot' }, grant, sig)
    await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/cookie-init', session: 'c-rot' }, grant, sig)
    const p1 = await broker.executeHttp({
      origin: fx.origin, method: 'POST', pathAndQuery: '/submit', session: 'c-rot', csrfBind: true,
      headers: { 'Content-Type': 'application/json' }, body: '{}',
    }, grant, sig)
    assert.equal(fx.requests.at(-1)?.headers['x-xsrf-token'], 'xsrf_rot_2')
    assert.ok(!JSON.stringify(p1).includes('xsrf_rot_2'), 'CSRF token must be dynamically redacted')

    // Meta tag extraction -> binds X-CSRF-Token
    await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/meta-init', session: 'c-meta' }, grant, sig)
    await broker.executeHttp({
      origin: fx.origin, method: 'POST', pathAndQuery: '/submit', session: 'c-meta', csrfBind: true,
      headers: { 'Content-Type': 'application/json' }, body: '{}',
    }, grant, sig)
    assert.equal(fx.requests.at(-1)?.headers['x-csrf-token'], 'meta_tok_111')

    // Hidden input extraction preserves detected field name in form POST
    await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/form-init', session: 'c-form' }, grant, sig)
    await broker.executeHttp({
      origin: fx.origin, method: 'POST', pathAndQuery: '/submit', session: 'c-form', csrfBind: true,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'user=bob',
    }, grant, sig)
    assert.ok(fx.requests.at(-1)?.body.includes('__RequestVerificationToken=hidden_tok_222'))

    // JSON token extraction binds JSON field + header
    await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/json-init', session: 'c-json' }, grant, sig)
    await broker.executeHttp({
      origin: fx.origin, method: 'POST', pathAndQuery: '/submit', session: 'c-json', csrfBind: true,
      headers: { 'Content-Type': 'application/json' }, body: '{"action":"save"}',
    }, grant, sig)
    const jsonSent = JSON.parse(fx.requests.at(-1)?.body ?? '{}')
    assert.equal(jsonSent.csrfToken, 'json_tok_333')
    assert.equal(fx.requests.at(-1)?.headers['x-csrf-token'], 'json_tok_333')

    // Clean no-op when jar has no CSRF token
    const noop = await broker.executeHttp({
      origin: fx.origin, method: 'POST', pathAndQuery: '/submit', session: 'c-empty', csrfBind: true,
      headers: { 'Content-Type': 'application/json' }, body: '{}',
    }, grant, sig)
    assert.equal(noop.status, 200)
    assert.equal(fx.requests.at(-1)?.headers['x-csrf-token'], undefined)
  })
})

// ============================================================================
// M2.3: authMutation Primitives & Dynamic Redaction
// ============================================================================

test('M2.3 authMutation: all 7 primitives mutate JWT on wire, mint canary when url omitted, enforce gates, and scrub empty-sig JWTs', async t => {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const publicJwk = publicKey.export({ format: 'jwk' })
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }) as string

  const canary = new CanaryBroker()
  await canary.startListener({ host: '127.0.0.1', port: 0 })
  t.after(() => canary.stopListener())

  const fx = await httpFixture((req, _b, res) => {
    const u = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (u.pathname === '/.well-known/jwks.json') {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ keys: [{ ...publicJwk, kid: 'k-rsa', use: 'sig', alg: 'RS256' }] }))
      return
    }
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ echoAuth: req.headers.authorization ?? '' }))
  })
  t.after(() => fx.close())

  const tmp = makeTempStore()
  t.after(() => tmp.close())
  const origJwt = makeSignedJwt({ alg: 'RS256', typ: 'JWT', kid: 'k-rsa' }, { sub: 'u1', role: 'user', exp: Math.floor(Date.now() / 1000) + 3600 })
  const broker = new RequestBroker({ rejectUnauthorized: false, canaryBroker: canary })
  const sig = AbortSignal.timeout(15_000)

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    const { projectId, runId, assignmentId } = setupApprovedRun(tmp.storage, fx.origin)
    const { id: pid } = createProjectPersona(tmp.storage, {
      requestId: randomUUID(),
      projectId,
      handle: 'jwt_p',
      roleLabel: 'User',
      originAllowlist: [fx.origin],
      authKind: 'bearer',
      secret: origJwt,
      canaryMarkers: [],
    })
    const personas = resolveRunPersonas(tmp.storage, projectId, [pid])
    const grant = makeLabGrant(fx.origin, { tier: 2, personas })
    // Zod rejects authMutation without persona
    assert.equal(replayStepSchema.safeParse({
      id: 's1', role: 'probe', description: 'missing persona',
      request: { origin: fx.origin, method: 'GET', pathAndQuery: '/', authMutation: { kind: 'alg_none' } },
    }).success, false)

    // Broker rejects missing persona, Tier < 2, and public claim_swap
    await assert.rejects(broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/', authMutation: { kind: 'alg_none' } }, grant, sig), BrokerDenied)
    await assert.rejects(broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/', persona: 'jwt_p', authMutation: { kind: 'alg_none' } }, makeLabGrant(fx.origin, { tier: 1, personas }), sig), BrokerDenied)
    await assert.rejects(broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/', persona: 'jwt_p', authMutation: { kind: 'claim_swap', claims: { role: 'admin' } } }, makePublicGrant(fx.origin, { tier: 2, personas }), sig), BrokerDenied)

    const cases = [
      { kind: 'alg_none' as const },
      { kind: 'strip_signature' as const },
      { kind: 'expired_replay' as const, skewSeconds: 7200 },
      { kind: 'rs256_to_hs256_jwks' as const },
      { kind: 'kid_inject' as const, value: 'key-override' },
      { kind: 'jku_x5u_canary' as const, header: 'jku' as const }, // omitted url -> auto-minted via CanaryBroker!
      { kind: 'claim_swap' as const, claims: { role: 'admin' } },
    ]
    const mutatedTokens: string[] = []
    for (const mut of cases) {
      const ex = await broker.executeHttp({
        origin: fx.origin, method: 'GET', pathAndQuery: '/api/me', persona: 'jwt_p', authMutation: mut, runId, assignmentId,
      }, grant, sig)
      const wireJwt = String(fx.requests.at(-1)?.headers.authorization ?? '').slice(7)
      assert.ok(wireJwt.length > 10 && wireJwt !== origJwt)
      mutatedTokens.push(wireJwt)
      const parts = wireJwt.split('.')
      const hdr = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as Record<string, unknown>
      const pay = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Record<string, unknown>
      if (mut.kind === 'alg_none') { assert.equal(hdr.alg, 'none'); assert.equal(parts[2], '') }
      if (mut.kind === 'strip_signature') assert.equal(parts[2], '')
      if (mut.kind === 'expired_replay') assert.ok(Number(pay.exp) < Math.floor(Date.now() / 1000))
      if (mut.kind === 'rs256_to_hs256_jwks') {
        assert.equal(hdr.alg, 'HS256')
        assert.equal(parts[2], createHmac('sha256', publicPem).update(`${parts[0]}.${parts[1]}`).digest('base64url'))
      }
      if (mut.kind === 'kid_inject') assert.equal(hdr.kid, 'key-override')
      if (mut.kind === 'jku_x5u_canary') assert.match(String(hdr.jku), /\/c\/guardian-canary-[a-f0-9]{24}/)
      if (mut.kind === 'claim_swap') assert.equal(pay.role, 'admin')

      assert.ok(!JSON.stringify(ex).includes(origJwt), `Original JWT leaked in exchange for ${mut.kind}`)
      assert.ok(!JSON.stringify(ex).includes(wireJwt), `Mutated JWT leaked in exchange for ${mut.kind}`)
    }

    // Inline verifier feedback scrubs both original and empty-signature mutated JWT
    const inline = await verifyReplaySpecInline({
      runId,
      assignmentId,
      attemptCount: 1,
      spec: {
        version: 1,
        kind: 'auth_protocol_proof',
        origin: fx.origin,
        protocol: 'jwt',
        title: 'JWT alg_none redaction',
        category: 'broken-access-control',
        cwe: 'CWE-347',
        severity: 'high',
        severityRationale: 'Test dynamic JWT redaction in InlineVerifyFeedback.',
        impact: 'Token bypass',
        remediation: 'Reject alg=none',
        recheckInstructions: 'Replay',
        steps: [
          { id: 'c1', role: 'control', description: 'valid', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/me', persona: 'jwt_p' } },
          { id: 'p1', role: 'probe', description: 'alg_none', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/me', persona: 'jwt_p', authMutation: { kind: 'alg_none' } } },
        ],
        assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: false, observed: .steps.p1.bodyPreview, expected: "redacted" }',
      },
      broker,
      backend: createJqBackend(),
      grant,
      signal: sig,
    })
    assert.ok(!JSON.stringify(inline).includes(origJwt))
    assert.ok(!JSON.stringify(inline).includes(mutatedTokens[0]))
  })
})

// ============================================================================
// M2.4: Tier-2 sandboxWriteAllowlist
// ============================================================================

test('M2.4 Tier-2 sandboxWriteAllowlist: explicit [] blocks even in local-lab, wildcard /actions* works, traversal & DELETE/multipart/destructive blocked', async t => {
  const fx = await httpFixture((_req, _b, res) => { res.end('{"ok":true}') })
  t.after(() => fx.close())
  const broker = new RequestBroker({ rejectUnauthorized: false })
  const sig = AbortSignal.timeout(10_000)

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    await assert.rejects(
      broker.executeHttp({ origin: fx.origin, method: 'POST', pathAndQuery: '/api/search', body: '{}' }, makeLabGrant(fx.origin, { tier: 2, sandboxWriteAllowlist: [] }), sig),
      BrokerDenied,
    )

    const grant = makeLabGrant(fx.origin, {
      tier: 2,
      sandboxWriteAllowlist: [
        { origin: fx.origin, method: 'POST', pathPattern: '/api/search' },
        { origin: fx.origin, method: 'POST', pathPattern: '/actions*' },
      ],
    })
    const ok1 = await broker.executeHttp({ origin: fx.origin, method: 'POST', pathAndQuery: '/api/search', body: '{"q":1}' }, grant, sig)
    const ok2 = await broker.executeHttp({ origin: fx.origin, method: 'POST', pathAndQuery: '/actions/run', body: '["1"]' }, grant, sig)
    assert.equal(ok1.status, 200)
    assert.equal(ok2.status, 200)

    await assert.rejects(broker.executeHttp({ origin: fx.origin, method: 'POST', pathAndQuery: '/api/search-admin', body: '{}' }, grant, sig), BrokerDenied)
    await assert.rejects(broker.executeHttp({ origin: fx.origin, method: 'POST', pathAndQuery: '/api/search/../admin', body: '{}' }, grant, sig), BrokerDenied)
    await assert.rejects(broker.executeHttp({ origin: fx.origin, method: 'DELETE', pathAndQuery: '/api/search' }, grant, sig), BrokerDenied)
    await assert.rejects(broker.executeHttp({ origin: fx.origin, method: 'POST', pathAndQuery: '/api/search', multipartParts: [{ name: 'f', contentType: 'text/plain', content: 'x' }] }, grant, sig), BrokerDenied)
    await assert.rejects(broker.executeHttp({ origin: fx.origin, method: 'POST', pathAndQuery: '/api/search', body: 'rm -rf /' }, grant, sig), BrokerDenied)
  })
})

// ============================================================================
// M2.5: ?_gcb= Cache-Buster Enforcement & cache_differential (#13)
// ============================================================================

test('M2.5 ?_gcb= enforcement and cache_differential (#13) confirms cached poison and dismisses MISS', async t => {
  const poisoned = new Map<string, string>()
  let serveHit = true
  const fx = await httpFixture((req, _b, res) => {
    const u = new URL(req.url ?? '/', 'http://127.0.0.1')
    const gcb = u.searchParams.get('_gcb') ?? ''
    const xfh = req.headers['x-forwarded-host']
    if (typeof xfh === 'string' && gcb) poisoned.set(gcb, xfh)
    if (poisoned.has(gcb) && serveHit) {
      res.setHeader('X-Cache', xfh ? 'MISS' : 'HIT')
      if (!xfh) res.setHeader('Age', '8')
      res.end(`HOST=${poisoned.get(gcb)}`)
      return
    }
    res.setHeader('X-Cache', 'MISS')
    res.end('HOST=clean')
  })
  t.after(() => fx.close())

  const broker = new RequestBroker({ rejectUnauthorized: false })
  const grant = makeLabGrant(fx.origin)
  const sig = AbortSignal.timeout(15_000)

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    await assert.rejects(broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/home', probeClass: 'cache_poison_deception' }, grant, sig), BrokerDenied)
    await assert.rejects(broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/home?_gcb=short', probeClass: 'cache_poison_deception' }, grant, sig), BrokerDenied)

    // ProbeDifferential auto-appends unique ?_gcb= and detects poisoning
    const diff = await probeDifferential({ probeClass: 'cache_poison_deception', origin: fx.origin, pathAndQuery: '/home?v=1' }, broker, grant, undefined, sig)
    assert.equal(diff.verdict, 'signal')

    // cache_differential schema rejects duplicate literal _gcb
    const dupGcb = '0123456789abcdef0123456789abcdef'
    assert.equal(declarativeReplaySpecSchema.safeParse({
      version: 1, kind: 'cache_differential', origin: fx.origin, targetOrigin: fx.origin,
      title: 'dup', category: 'misconfig-exposure', cwe: 'CWE-444', severity: 'high',
      severityRationale: 'dup check', impact: 'cache', remediation: 'fix', recheckInstructions: 'recheck',
      controlPath: `/home?_gcb=${dupGcb}`, probePath: `/home?_gcb=${dupGcb}`,
      assertionsJq: '{ controlPassed: true, confirmed: true, observed: "a", expected: "b" }',
    }).success, false)

    // ReplayVerifier cache_differential confirms HIT and dismisses MISS
    const ok = await verifyReplaySpec({
      spec: {
        version: 1, kind: 'cache_differential', origin: fx.origin, targetOrigin: fx.origin,
        title: 'Cache poison hit', category: 'misconfig-exposure', cwe: 'CWE-444', severity: 'high',
        severityRationale: 'Unkeyed X-Forwarded-Host poisoned shared cache.', impact: 'Cache poison',
        remediation: 'Ignore X-Forwarded-Host', recheckInstructions: 'Replay',
        controlPath: '/home?_gcb={{control_gcb}}',
        probePath: '/home?_gcb={{probe_gcb}}',
        poisonHeaders: { 'X-Forwarded-Host': 'evil-cache.invalid' },
        assertionsJq: '{ controlPassed: (.control.status == 200), confirmed: (.cacheProof.cacheHitObserved and .cacheProof.poisonPersistedToVictim), observed: .verify.bodyPreview, expected: "HOST=clean" }',
      },
      broker, backend: createJqBackend(), grant, signal: sig,
    })
    assert.equal(ok.verdict, 'confirmed')

    serveHit = false
    const miss = await verifyReplaySpec({
      spec: {
        version: 1, kind: 'cache_differential', origin: fx.origin, targetOrigin: fx.origin,
        title: 'Cache poison miss', category: 'misconfig-exposure', cwe: 'CWE-444', severity: 'high',
        severityRationale: 'Should dismiss on MISS.', impact: 'No poisoning observed on clean MISS.',
        remediation: 'No action needed when uncached.', recheckInstructions: 'Replay',
        controlPath: '/home?_gcb={{control_gcb}}',
        probePath: '/home?_gcb={{probe_gcb}}',
        poisonHeaders: { 'X-Forwarded-Host': 'evil-cache.invalid' },
        assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "clean" }',
      },
      broker, backend: createJqBackend(), grant, signal: sig,
    })
    assert.equal(miss.verdict, 'dismissed')
  })
})

// ============================================================================
// M2.6: ScopedBrowser.runBrowserSession & browser_chain Integration
// ============================================================================

test('M2.6 ScopedBrowser.runBrowserSession: persistent page/localStorage across reusePage, reset on control<->probe/resetContext, Tier-2 POST passthrough & M1.10 fallback', async t => {
  const tp = await httpFixture((_req, _b, res) => { res.end('console.log(1)') })
  t.after(() => tp.close())

  const fx = await httpFixture((req, body, res) => {
    const u = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (u.pathname === '/api/save' && req.method === 'POST') {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ saved: body }))
      return
    }
    res.setHeader('Content-Type', 'text/html')
    res.end(`<html><body>
      <script src="${tp.origin}/blocked.js"></script>
      <input id="inp" />
      <button id="btn" onclick="localStorage.setItem('k', document.getElementById('inp').value); document.getElementById('out').innerHTML = document.getElementById('inp').value;">Go</button>
      <div id="out"></div>
      <div id="ls"></div>
      <script>document.getElementById('ls').textContent = 'LS=' + (localStorage.getItem('k') || 'EMPTY');</script>
    </body></html>`)
  })
  t.after(() => fx.close())

  const broker = new RequestBroker({ rejectUnauthorized: false })
  const browser = new ScopedBrowser(broker)
  const grant = makeLabGrant(fx.origin, {
    tier: 2,
    sandboxWriteAllowlist: [{ origin: fx.origin, method: 'POST', pathPattern: '/api/save' }],
  })
  const sig = AbortSignal.timeout(45_000)

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    const res = await browser.runBrowserSession([
      { id: 'c1', role: 'control', origin: fx.origin, pathAndQuery: '/', action: 'fill', selector: '#inp', value: 'safe-ctrl' },
      { id: 'c2', role: 'control', origin: fx.origin, reusePage: true, action: 'click', selector: '#btn', builtinCheck: 'storage_keys' },
      // Transition control -> probe must reset context & localStorage
      { id: 'p1', role: 'probe', origin: fx.origin, pathAndQuery: '/', action: 'fill', selector: '#inp', value: '<img src=x onerror=1>', enableSinkHook: true, builtinCheck: 'storage_keys' },
      { id: 'p2', role: 'probe', origin: fx.origin, reusePage: true, action: 'click', selector: '#btn', enableSinkHook: true },
    ], grant, sig)

    assert.equal(res.length, 4)
    assert.equal(tp.requests.length, 0, 'Third-party script must never bypass RequestBroker')
    assert.ok(res[1].localStorageKeys.includes('k'))
    assert.ok(res[2].domSnippet.includes('LS=EMPTY'), 'control -> probe transition must reset localStorage')
    assert.ok(res[3].domSinkTraces.some(tr => tr.sink === 'innerHTML' && tr.preview.includes('<img src=x onerror=1>')))

    // M1.10 fakeBrowser fallback compatibility (visitPage only, no runBrowserSession)
    let visitCount = 0
    const fakeBrowser = {
      async visitPage() {
        visitCount += 1
        return {
          origin: fx.origin, finalUrl: `${fx.origin}/`, title: 'Fake', status: 200, domSnippet: '<div>ok</div>',
          links: [], forms: [], xhrRequests: [], blockedOrigins: [], consoleMessages: [],
          postMessageListeners: { count: 0, hasOnMessage: false, handlers: [], observedEvents: 0, canaryHandledWithoutOriginCheck: false },
          cookieNames: [], localStorageKeys: [], sessionStorageKeys: [],
          canaryCheck: { token: null, triggered: false, detail: null }, domSinkTraces: [],
          exchangeIds: [], exchanges: [], durationMs: 1,
        }
      },
    } as unknown as ScopedBrowser
    const fbRes = await verifyReplaySpec({
      spec: {
        version: 1, kind: 'browser_chain', origin: fx.origin, title: 'Fallback check',
        category: 'xss', cwe: 'CWE-79', severity: 'medium', severityRationale: 'Fallback check',
        impact: 'Cross-site scripting in browser DOM.', remediation: 'Escape untrusted HTML', recheckInstructions: 'Replay',
        steps: [
          { id: 'c1', role: 'control', description: 'ctrl', origin: fx.origin, pathAndQuery: '/', action: 'navigate' },
          { id: 'p1', role: 'probe', description: 'probe', origin: fx.origin, pathAndQuery: '/', action: 'navigate' },
        ],
        assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: true, observed: "ok", expected: "ok" }',
      } as unknown,
      broker, browser: fakeBrowser, backend: createJqBackend(), grant, signal: sig,
    })
    assert.equal(visitCount, 2)
    assert.equal(fbRes.verdict, 'confirmed')
  })
})

// ============================================================================
// M2.7 & M2.8: Universal 7 Encodings, Expanded sqli_boolean & sql_time_diff (#14)
// ============================================================================

test('M2.7 & M2.8 universal encodings + expanded sqli_boolean + sql_time_diff (#14) non-overlap and public gate', async t => {
  let flip = 0
  let jitterMode = false
  const seenSqlPayloads: string[] = []
  const fx = await httpFixture(async (req, body, res) => {
    const u = new URL(req.url ?? '/', 'http://127.0.0.1')
    res.setHeader('Content-Type', 'application/json')
    if (u.pathname === '/bool-form') {
      const sp = new URLSearchParams(body)
      const q = sp.get('q') ?? ''
      seenSqlPayloads.push(q)
      const m = /AND\s+(\d+)=(\d+)/i.exec(q)
      const isTrue = q === '1' || (m !== null && m[1] === m[2])
      res.end(JSON.stringify({ rows: isTrue ? ['alice', 'bob', 'carol'] : [] }))
      return
    }
    if (u.pathname === '/bool-xml') {
      seenSqlPayloads.push(body)
      const m = /AND\s+(\d+)=(\d+)/i.exec(body)
      const isTrue = body.includes('<id>1</id>') || (m !== null && m[1] === m[2])
      res.end(JSON.stringify({ rows: isTrue ? ['row1', 'row2'] : [] }))
      return
    }
    if (u.pathname === '/time') {
      flip += 1
      const id = u.searchParams.get('id') ?? ''
      if (jitterMode) {
        if (flip === 1) await delay(2200)
      } else if (/pg_sleep|SLEEP|WAITFOR|RANDOMBLOB/i.test(id)) {
        await delay(1650)
      }
      res.end(JSON.stringify({ ok: true }))
      return
    }
    res.end('{}')
  })
  t.after(() => fx.close())

  const broker = new RequestBroker({ rejectUnauthorized: false })
  const grant = makeLabGrant(fx.origin, { tier: 3, isIdempotentPostAllowed: () => true })
  const sig = AbortSignal.timeout(45_000)

  // Verify agent-session constants include all 7 encodings & 13 probe classes
  assert.equal(probeParamLocations.length, 7)
  assert.equal(differentialProbeClasses.length, 13)

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    for (const loc of ['form', 'xml'] as const) {
      const rv = await verifyReplaySpec({
        spec: {
          version: 1, kind: 'sql_boolean_diff', origin: fx.origin, targetOrigin: fx.origin,
          title: `Boolean diff (${loc})`, category: 'injection-input', cwe: 'CWE-89', severity: 'high',
          severityRationale: 'Boolean SQLi differential', impact: 'SQL injection via parameter.', remediation: 'Use parameterized queries', recheckInstructions: 'Replay',
          method: 'POST', pathAndQuery: loc === 'form' ? '/bool-form' : '/bool-xml',
          paramName: loc === 'form' ? 'q' : 'id', paramLocation: loc, baselineValue: '1', quoteStyle: 'single',
          assertionsJq: '{ controlPassed: (.sqlDiff.controlPassed == true), confirmed: (.sqlDiff.passed == true), observed: "diff", expected: "none" }',
        },
        broker, backend: createJqBackend(), grant, signal: sig,
      })
      assert.equal(rv.verdict, 'confirmed', `Expected sql_boolean_diff (${loc}) to confirm`)
    }

    // sql_time_diff schema bounds
    assert.equal(sqlTimeDiffReplaySpecSchema.safeParse({
      version: 1, kind: 'sql_time_diff', origin: fx.origin, targetOrigin: fx.origin,
        title: 'Bad delay bounds', category: 'injection-input', cwe: 'CWE-89', severity: 'high',
        severityRationale: 'bounds check', impact: 'SQL injection timing impact.', remediation: 'Use parameterized queries', recheckInstructions: 'recheck',
      pathAndQuery: '/time?id=1', paramName: 'id', paramLocation: 'query', delayMs: 400,
      assertionsJq: '{ controlPassed: true, confirmed: true, observed: "x", expected: "y" }',
    }).success, false)

    // Public target below Tier 3 sends 0 requests
    let pubHits = 0
    const pubBroker = new RequestBroker({
      resolve: async () => [publicAddr],
      transport: async () => { pubHits += 1; return { status: 200, headers: {}, body: 'ok' } },
    })
    const pubRes = await verifyReplaySpec({
      spec: {
        version: 1, kind: 'sql_time_diff', origin: appOrigin, targetOrigin: appOrigin,
        title: 'Public gated', category: 'injection-input', cwe: 'CWE-89', severity: 'high',
        severityRationale: 'gated check', impact: 'SQL injection timing impact.', remediation: 'Use parameterized queries', recheckInstructions: 'recheck',
        pathAndQuery: '/time?id=1', paramName: 'id', paramLocation: 'query', delayMs: 1600,
        assertionsJq: '{ controlPassed: true, confirmed: true, observed: "x", expected: "y" }',
      },
      broker: pubBroker, backend: createJqBackend(), grant: makePublicGrant(appOrigin, { tier: 2 }), signal: sig,
    })
    assert.equal(pubHits, 0)
    assert.equal(pubRes.verdict, 'inconclusive')

    // Local-lab clean non-overlapping delay confirms
    jitterMode = false
    const timeOk = await verifyReplaySpec({
      spec: {
        version: 1, kind: 'sql_time_diff', origin: fx.origin, targetOrigin: fx.origin,
        title: 'Time diff pass', category: 'injection-input', cwe: 'CWE-89', severity: 'high',
        severityRationale: '3 non-overlapping rounds', impact: 'SQL injection timing impact.', remediation: 'Parameterize', recheckInstructions: 'Replay',
        pathAndQuery: '/time?id=1', paramName: 'id', paramLocation: 'query', delayMs: 1600, dialect: 'postgres',
        assertionsJq: '{ controlPassed: .sqlTimeDiff.controlPassed, confirmed: .sqlTimeDiff.passed, observed: "delayed", expected: "constant" }',
      },
      broker, backend: createJqBackend(), grant, signal: sig,
    })
    assert.equal(timeOk.verdict, 'confirmed')

    // Jittery/overlapping baseline dismisses
    jitterMode = true
    flip = 0
    const timeJitter = await verifyReplaySpec({
      spec: {
        version: 1, kind: 'sql_time_diff', origin: fx.origin, targetOrigin: fx.origin,
        title: 'Time diff jitter', category: 'injection-input', cwe: 'CWE-89', severity: 'high',
        severityRationale: 'Should dismiss on overlap', impact: 'No confirmed timing differential.', remediation: 'No action needed.', recheckInstructions: 'Replay',
        pathAndQuery: '/time?id=1', paramName: 'id', paramLocation: 'query', delayMs: 1600, dialect: 'postgres',
        assertionsJq: '{ controlPassed: .sqlTimeDiff.controlPassed, confirmed: .sqlTimeDiff.passed, observed: "overlap", expected: "clean" }',
      },
      broker, backend: createJqBackend(), grant, signal: sig,
    })
    assert.equal(timeJitter.verdict, 'dismissed')
  })
})

// ============================================================================
// M2.9 & M2.10: auth_protocol_proof (#12), xss_context, xxe_canary, mass_assignment
// ============================================================================

test('M2.9 & M2.10 new probe classes and auth_protocol_proof OOB jku_x5u_canary', async t => {
  const canary = new CanaryBroker()
  await canary.startListener({ host: '127.0.0.1', port: 0 })
  t.after(() => canary.stopListener())

  let role = 'user'
  const fx = await httpFixture(async (req, body, res) => {
    const u = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (u.pathname === '/xss') {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body><input value="${u.searchParams.get('q') ?? ''}"></body></html>`)
      return
    }
    if (u.pathname === '/xxe') {
      const m = /https?:\/\/[^\s"'>]+guardian-canary-[a-f0-9]+[^\s"'>]*/i.exec(body)
      if (m) await fetch(m[0]).catch(() => {})
      res.setHeader('Content-Type', 'application/xml')
      res.end('<ok/>')
      return
    }
    if (u.pathname === '/profile') {
      res.setHeader('Content-Type', 'application/json')
      if (req.method === 'POST') {
        const parsed = JSON.parse(body || '{}') as { role?: string }
        if (parsed.role) role = parsed.role
      }
      res.end(JSON.stringify({ id: 1, role }))
      return
    }
    if (u.pathname === '/jku-auth') {
      const tok = String(req.headers.authorization ?? '').slice(7)
      const hdr = JSON.parse(Buffer.from(tok.split('.')[0], 'base64url').toString('utf8')) as { jku?: string }
      if (hdr.jku) await fetch(hdr.jku).catch(() => {})
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ ok: true }))
      return
    }
    res.end('ok')
  })
  t.after(() => fx.close())

  const tmp = makeTempStore()
  t.after(() => tmp.close())
  const origJwt = makeSignedJwt({ alg: 'RS256', typ: 'JWT' }, { sub: 'u1' })
  const broker = new RequestBroker({ rejectUnauthorized: false, canaryBroker: canary })
  const sig = AbortSignal.timeout(20_000)

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    const { projectId, runId } = setupApprovedRun(tmp.storage, fx.origin)
    const { id: pid } = createProjectPersona(tmp.storage, {
      requestId: randomUUID(), projectId, handle: 'jku_p', roleLabel: 'User',
      originAllowlist: [fx.origin], authKind: 'bearer', secret: origJwt, canaryMarkers: [],
    })
    const personas = resolveRunPersonas(tmp.storage, projectId, [pid])
    const grant = makeLabGrant(fx.origin, { personas, isIdempotentPostAllowed: () => true })
    const xss = await probeDifferential({ probeClass: 'xss_context', origin: fx.origin, pathAndQuery: '/xss?q=1', param: 'q' }, broker, grant, canary, sig)
    assert.equal(xss.verdict, 'signal')
    assert.equal(xss.details.context, 'html_attr')
    assert.equal(xss.details.suggestedReplayKind, 'browser_chain')

    await assert.rejects(
      probeDifferential({ probeClass: 'xxe_canary', origin: fx.origin, pathAndQuery: '/xxe', method: 'POST', customPayload: '<!DOCTYPE x [<!ENTITY f SYSTEM "file:///etc/passwd">]><r>&f;</r>' }, broker, grant, canary, sig),
      BrokerDenied,
    )
    const xxe = await probeDifferential({ probeClass: 'xxe_canary', origin: fx.origin, pathAndQuery: '/xxe', method: 'POST', runId }, broker, grant, canary, sig)
    assert.equal(xxe.verdict, 'signal')

    const ma = await probeDifferential({ probeClass: 'mass_assignment', origin: fx.origin, pathAndQuery: '/profile', method: 'POST', candidateFields: ['role'] }, broker, grant, canary, sig)
    assert.equal(ma.verdict, 'signal')

    const authProof = await verifyReplaySpec({
      spec: {
        version: 1, kind: 'auth_protocol_proof', origin: fx.origin, protocol: 'jwt',
        title: 'JKU canary fetch', category: 'broken-access-control', cwe: 'CWE-347', severity: 'high',
        severityRationale: 'Server fetches untrusted jku URL.', impact: 'Key spoofing', remediation: 'Pin JWKS', recheckInstructions: 'Replay',
        steps: [
          { id: 'c1', role: 'control', description: 'valid', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/jku-auth', persona: 'jku_p' } },
          { id: 'p1', role: 'probe', description: 'jku canary', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/jku-auth', persona: 'jku_p', authMutation: { kind: 'jku_x5u_canary', header: 'jku' } } },
        ],
        assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.canaryProof.probeTriggered == true and .canaryProof.controlTriggered == false), observed: "jku_oob", expected: "no fetch" }',
      } as unknown,
      broker, canaryBroker: canary, backend: createJqBackend(), grant, signal: sig, runId,
    })
    assert.equal(authProof.verdict, 'confirmed')
  })
})

// ============================================================================
// M2.11 & M2.12: Second-Order Canary Ledger & Zero-LLM Invariant #4
// ============================================================================

test('M2.11 & M2.12 second-order canary ledger (cross-endpoint/persona vs same-endpoint ignored) & Zero-LLM telemetry isolation', async t => {
  const tmp = makeTempStore()
  t.after(() => tmp.close())
  const canary = new CanaryBroker({ storage: tmp.storage })
  await canary.startListener({ host: '127.0.0.1', port: 0 })
  t.after(() => canary.stopListener())

  let currentMarker = ''
  const fx = await httpFixture((req, _b, res) => {
    const u = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (u.pathname === '/profile') {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<div>${currentMarker}</div>`)
      return
    }
    if (u.pathname === '/admin/audit') {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body><div id="feed"></div><script>document.getElementById('feed').textContent='${currentMarker}';</script></body></html>`)
      return
    }
    res.end('ok')
  })
  t.after(() => fx.close())

  const broker = new RequestBroker({ rejectUnauthorized: false, storage: tmp.storage })
  const browser = new ScopedBrowser(broker, { storage: tmp.storage })
  const grant = makeLabGrant(fx.origin)
  const sig = AbortSignal.timeout(30_000)

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    const { runId, assignmentId } = setupApprovedRun(tmp.storage, fx.origin)
    const minted = canary.mintSecondOrderCanary({
      runId,
      assignmentId,
      injectedOrigin: fx.origin,
      injectedEndpoint: '/profile',
      injectedParam: 'bio',
      injectedPersona: 'user_a',
      storage: tmp.storage,
    })
    assert.match(minted.marker, /^gn2o_[a-f0-9]{8}$/)
    currentMarker = minted.marker
    // Same endpoint + same persona (null/user_a) check: note injectedPersona='user_a', so test matching persona ignored
    // Wait: using persona undefined vs 'user_a' -> let's mint another marker with injectedPersona=null for exact self-reflection check
    const selfMinted = canary.mintSecondOrderCanary({
      runId,
      assignmentId,
      injectedOrigin: fx.origin,
      injectedEndpoint: '/profile',
      injectedParam: 'bio',
      injectedPersona: null,
      storage: tmp.storage,
    })
    currentMarker = selfMinted.marker
    await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/profile', runId, assignmentId }, grant, sig)
    assert.equal(tmp.storage.listSecondOrderCanaries(runId, 'surfaced').length, 0, 'Same-endpoint + same-persona self-reflection must not mark surfaced')

    // Cross-endpoint DOM surfacing via ScopedBrowser
    currentMarker = minted.marker
    await browser.visitPage({ origin: fx.origin, pathAndQuery: '/admin/audit', runId, assignmentId }, grant, sig)
    const surfaced = tmp.storage.listSecondOrderCanaries(runId, 'surfaced')
    assert.equal(surfaced.length, 1)
    assert.equal(surfaced[0].marker, minted.marker)

    const facts = tmp.storage.listFacts(runId, { includeTainted: false, limit: 20 })
    assert.ok(facts.some(f => String(f.kind).includes('second_order') && f.summary.includes(minted.marker)))
    assert.equal(tmp.storage.runDetail(runId).findings.length, 0, 'Second-order surfacing must never auto-create confirmed findings')

    // Zero-LLM Invariant #4: forged lab_telemetry & /evidence/lab-telemetry/ never exposed to ReplayVerifier
    const telDir = join(tmp.dir, 'evidence', 'lab-telemetry')
    mkdirSync(telDir, { recursive: true })
    const forgedId = randomUUID()
    writeFileSync(join(telDir, `${forgedId}.json`), JSON.stringify({ confirmed: true, telemetry: { confirmed: true } }))
    tmp.storage.insertLabTelemetry({
      runId, exchangeId: forgedId, traceId: forgedId, routesHit: ['/profile'],
      newLinesCovered: 10, sinkEventsCount: 1, hasUnhandledException: true, artifactId: forgedId,
    })
    const rv = await verifyReplaySpec({
      spec: {
        version: 1, kind: 'http_chain', origin: fx.origin, title: 'Telemetry isolation',
        category: 'injection-input', cwe: 'CWE-89', severity: 'high',
        severityRationale: 'Verify ReplayVerifier ignores lab_telemetry.', impact: 'No confirmed runtime impact.',
        remediation: 'Keep ReplayVerifier isolated.', recheckInstructions: 'Replay',
        steps: [
          { id: 'c1', role: 'control', description: 'ctrl', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/ok' } },
          { id: 'p1', role: 'probe', description: 'probe', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/ok' } },
        ],
        assertionsJq: '{ controlPassed: true, confirmed: ((.telemetry.confirmed // false) == true), observed: "none", expected: "true" }',
      },
      broker, backend: createJqBackend(), grant, signal: sig, storage: tmp.storage, runId, assignmentId,
    })
    assert.equal(rv.verdict, 'dismissed', JSON.stringify(rv.outcome))
  })
})
