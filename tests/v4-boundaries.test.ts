/**
 * Kovo v4 Zero-Trust Boundary Suite (SPEC-v4 §2 invariants, §7 threat model, §8 release gates).
 *
 * Covers all 8 mandatory v4 zero-trust boundary controls:
 *   V4-B1: session-jar isolation, BVA, control/probe separation, scope revocation purge, zero leak
 *   V4-B2: authMutation (all 7 kinds) wire verification & dynamic redact() zero-leak
 *   V4-B3: mandatory ?_gcb= cache-buster enforcement & cache_differential isolation
 *   V4-B4: Tier-2 sandboxWriteAllowlist (safe POST vs DELETE/multipart/non-allowlist/destructive)
 *   V4-B5: LabRunner multi-service --internal isolation, compose sanitization, egress/gateway/orphan checks
 *   V4-B6: local-lab IAST secret masking, 64 KiB cap, public rejection, ReplayVerifier isolation
 *   V4-B7: Nuclei transpiler Zod rejection (TemplateValidationError) & src/templates/compiled/ gate
 *   V4-B8: verifyReplaySpecInline Zero-LLM integrity, sanitized feedback, retry cap, static_verified tier
 *
 * Pre-merge TypeScript safety:
 *   Uses dynamic module loading (`loadV4Module`) + structural contract casts (`as unknown as ...`)
 *   + `.safeParse(... as unknown)` + `storage.client` SQLite assertions so `npm run check` passes cleanly
 *   before M1–M6 merge, while failing loudly (NEVER skipping) if a required v4 export/module is missing.
 */
import assert from 'node:assert/strict'
import { createHmac, generateKeyPairSync, randomUUID } from 'node:crypto'
import { execFile } from 'node:child_process'
import { once } from 'node:events'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { pathToFileURL } from 'node:url'
import { promisify } from 'node:util'
import { newProject } from '../src/domain.ts'
import type { ApprovedEndpointPattern, LabConfig as DomainLabConfig } from '../src/domain.ts'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { LabRunner, assertLocalLabAllowed } from '../src/server/lab-runner.ts'
import type { LabConfig } from '../src/server/lab-runner.ts'
import { createProjectPersona, resolveRunPersonas } from '../src/server/persona-vault.ts'
import { verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { Store } from '../src/server/store.ts'
import { probeDifferential } from '../src/server/surface-engine.ts'
import type { ProbeDifferentialRequest } from '../src/server/surface-engine.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'
import { loadSafeTemplates, parseSafeTemplateYaml, TemplateValidationError } from '../src/templates/loader.ts'
import { createSuiteBMockRepo } from './v3-fullstack-lab/mock-repo.ts'

const exec = promisify(execFile)
const repoRootDir = resolve(new URL('..', import.meta.url).pathname)

const RAW_STRIPE = 'sk_live_TESTFIXTURE000000000000000000'
const RAW_AWS = 'AKIAIOSFODNN7EXAMPLE'
const GCB_REGEX = /^[a-f0-9-]{16,36}$/i

// ----------------------------------------------------------------------------
// Structural v4 Contracts & Dynamic Module Loader (TS-safe before M1–M6 merge)
// ----------------------------------------------------------------------------

interface V4InlineVerifyFeedback {
  verdict: 'confirmed' | 'static_verified' | 'dismissed' | 'inconclusive'
  verificationTier?: string
  failedStepId?: string
  controlPassed: boolean
  requireControlNonErrorTriggered?: boolean
  spaCatchallMatched?: boolean
  spaSimilarityScore?: number
  canaryTriggered?: boolean
  jqError?: string
  assertionSummary?: { observed: string; expected: string; reason?: string }
  stepStatuses: Array<{ id: string; role: string; status: number | null; mediaType?: string; bodyLen: number }>
  retriesRemaining: number
}

interface V4InlineVerifyResult {
  feedback: V4InlineVerifyFeedback
  replay: {
    verdict: 'confirmed' | 'static_verified' | 'dismissed' | 'inconclusive'
    verificationTier?: string
    outcome: { confirmed: boolean; controlPassed: boolean; observed: string; expected: string; reason?: string }
    exchangeIds: string[]
    exchanges: BrokerExchangeResult[]
    evidencePayload: Record<string, unknown>
    evidenceSha256: string
  }
}

interface V4AuthMutation {
  kind:
    | 'alg_none'
    | 'strip_signature'
    | 'expired_replay'
    | 'rs256_to_hs256_jwks'
    | 'kid_inject'
    | 'jku_x5u_canary'
    | 'claim_swap'
  skewSeconds?: number
  jwksUrl?: string
  value?: string
  header?: 'jku' | 'x5u'
  claims?: Record<string, string | number | boolean>
}

interface V4BrokerHttpRequest extends Omit<
  BrokerHttpRequest,
  'session' | 'csrfBind' | 'authMutation' | 'traceId' | 'probeClass' | 'runId' | 'assignmentId'
> {
  session?: string
  csrfBind?: boolean | { headerName?: string; fieldName?: string; cookieName?: string }
  authMutation?: V4AuthMutation
  traceId?: string
  probeClass?: string
  runId?: string
  assignmentId?: string
}

function asBrokerRequest(req: V4BrokerHttpRequest): BrokerHttpRequest {
  return req as unknown as BrokerHttpRequest
}

interface V4Grant extends Grant {
  sandboxWriteAllowlist?: ApprovedEndpointPattern[]
  scopeRevision?: number
}

interface V4BrokerContract {
  revokeOrigin?: (origin: string) => void
  revokeScope?: (scopeRevision: number) => void
}

interface V4LabServiceSpec {
  name: string
  image?: string
  command?: string
  internalPort?: number
  healthPath?: string
  env?: Record<string, string>
}

interface V4LabConfig extends LabConfig {
  services?: V4LabServiceSpec[]
  seedCommand?: string
  iastEnabled?: boolean
  iastRuntime?: 'node' | 'python' | 'generic'
}

interface V4LabTargetHandle {
  runId: string
  networkName: string
  containerName: string
  origin: string
  baseUrls?: Record<string, string>
  seededPersonas?: Array<{ handle: string; roleLabel?: string; authKind?: string }>
  telemetryDir?: string
  sanitizedRepoDir: string
}

interface V4StoreContract {
  initV4Schema?: () => void
  insertLabTelemetry?: (input: {
    runId: string
    exchangeId: string
    traceId?: string
    routesHit?: string[]
    newLinesCovered?: number
    sinkEventsCount?: number
    hasUnhandledException?: boolean
    artifactId?: string
    rawPayload?: unknown
  }) => unknown
  listLabTelemetry?: (runId: string) => Array<Record<string, unknown>>
  createReplaySpec?: (input: Record<string, unknown>) => { id: string }
}

interface V4TranspilerModule {
  transpileNucleiTemplate?: (yamlSource: string, opts?: Record<string, unknown>) => unknown
  transpileNucleiDirectory?: (inputDir: string, outputDir: string, opts?: Record<string, unknown>) => Promise<{
    transpiled: number
    rejected: Array<{ file: string; reason: string }>
  }>
}

async function loadV4Module<T>(relPathFromRepoRoot: string, description: string): Promise<T> {
  const abs = join(repoRootDir, relPathFromRepoRoot)
  assert.ok(existsSync(abs), `Required Kovo v4 module missing (${description}): ${abs}`)
  return (await import(pathToFileURL(abs).href)) as T
}

function assertExportFn<T extends (...args: never[]) => unknown>(
  mod: Record<string, unknown>,
  name: string,
  moduleLabel: string,
): T {
  const candidate = mod[name]
  assert.equal(typeof candidate, 'function', `Expected function export "${name}" on ${moduleLabel}`)
  return candidate as T
}

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

async function startLoopbackServer(
  handler: (req: IncomingMessage, res: ServerResponse, body: string) => void | Promise<void>,
) {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', chunk => chunks.push(Buffer.from(chunk)))
    req.on('end', () => {
      Promise.resolve(handler(req, res, Buffer.concat(chunks).toString('utf8'))).catch(err => {
        if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain' })
        res.end(err instanceof Error ? err.message : String(err))
      })
    })
  }).listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address()
  if (!addr || typeof addr === 'string') throw new Error('Failed to bind loopback server')
  return {
    origin: `http://127.0.0.1:${addr.port}`,
    port: addr.port,
    close: () => new Promise<void>(resolveClose => {
      server.closeAllConnections()
      server.close(() => resolveClose())
    }),
  }
}

function makeLabGrant(origin: string, overrides: Partial<V4Grant> = {}): V4Grant {
  return {
    origin,
    tier: 2,
    maxRpsPerOrigin: 50,
    allowLocalLab: true,
    canRead: candidate => candidate === origin,
    audit: () => {},
    ...overrides,
  }
}

function makeSignedJwt(header: Record<string, unknown>, payload: Record<string, unknown>, secret = 'test-signing-key'): string {
  const h = Buffer.from(JSON.stringify(header)).toString('base64url')
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const sig = createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url')
  return `${h}.${p}.${sig}`
}

function setupProjectAndRun(dir: string, env: 'public' | 'local-lab', origin: string, tier: 0 | 1 | 2 | 3 = 2) {
  const storage = new Store(dir)
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: `v4-boundary-${env}`,
    seeds: [origin],
    environment: env,
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId,
    goal: 'Verify v4 zero-trust boundaries.',
    sourceMode: 'public',
    capabilityTier: tier,
    budgetUsd: 5,
    budgetRequests: 200,
    maxRpsPerOrigin: 30,
    workerConcurrency: 2,
    workerMaxTurns: 20,
  })
  const assignmentId = randomUUID()
  storage.client.prepare(
    `INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at)
     VALUES (?, ?, 'investigation', 'running', 1, 1, ?, '[]', ?, 'Boundary Check', 'Verify boundary', ?)`,
  ).run(assignmentId, runId, randomUUID(), JSON.stringify([origin]), Date.now())
  return { storage, projectId, runId, assignmentId }
}

// ============================================================================
// V4-B1: session-jar isolation, BVA, control/probe separation & scope purge
// ============================================================================

test('V4-B1 session-jar isolation: regex BVA, origin/jar cookie scoping, control vs probe isolation, scope revocation purge, and zero raw cookie leaks', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v4-b1-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  const secretCookie = 'SECRET_JAR_COOKIE_123_NEVER_LEAK'
  const origin1SeenCookies: Array<{ path: string; cookie: string | null }> = []
  const origin2SeenCookies: Array<{ path: string; cookie: string | null }> = []

  const server1 = await startLoopbackServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    origin1SeenCookies.push({ path: url.pathname, cookie: req.headers.cookie ?? null })
    if (url.pathname === '/set-cookie') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': `sid=${secretCookie}; HttpOnly; Path=/`,
      }).end(JSON.stringify({ ok: true }))
      return
    }
    if (url.pathname === '/set-scoped-cookies') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': [
          'admin_sid=ADMIN_PATH_ONLY_123; Path=/admin; HttpOnly',
          'sec_sid=SECURE_ONLY_456; Secure; Path=/',
        ],
      }).end(JSON.stringify({ ok: true }))
      return
    }
    if (url.pathname === '/set-vault-collision') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': [
          'vault_auth=OVERWRITTEN_BAD; Path=/',
          'csrf_jar=CSRF_VAL_777; Path=/',
        ],
      }).end(JSON.stringify({ ok: true }))
      return
    }
    if (url.pathname === '/echo-cookie' || url.pathname === '/admin/echo' || url.pathname === '/public/echo') {
      const rawCookie = req.headers.cookie ?? ''
      const cookieNames = rawCookie
        .split(';')
        .map(s => s.trim().split('=')[0])
        .filter(Boolean)
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({
        hasSid: rawCookie.includes(secretCookie),
        cookieNames,
        hasAdmin: rawCookie.includes('ADMIN_PATH_ONLY_123'),
        hasSec: rawCookie.includes('SECURE_ONLY_456'),
        hasVaultAuth: rawCookie.includes('VAULT_AUTH_SECRET_999'),
        hasVaultOverwrite: rawCookie.includes('OVERWRITTEN_BAD'),
        hasCsrf: rawCookie.includes('CSRF_VAL_777'),
        rawEcho: rawCookie || null,
      }))
      return
    }
    res.writeHead(404).end('not found')
  })
  t.after(() => server1.close())

  const server2 = await startLoopbackServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    origin2SeenCookies.push({ path: url.pathname, cookie: req.headers.cookie ?? null })
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({
      hasSid: (req.headers.cookie ?? '').includes(secretCookie),
    }))
  })
  t.after(() => server2.close())

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const { storage, projectId, runId, assignmentId } = setupProjectAndRun(dir, 'local-lab', server1.origin, 2)
    t.after(() => storage.close())

    const { id: vaultPersonaId } = createProjectPersona(storage, {
      requestId: randomUUID(),
      projectId,
      handle: 'cookie_vault',
      roleLabel: 'CookieVaultUser',
      originAllowlist: [server1.origin],
      authKind: 'cookie',
      secret: 'vault_auth=VAULT_AUTH_SECRET_999',
      canaryMarkers: [],
    })
    const personas = resolveRunPersonas(storage, projectId, [vaultPersonaId])
    const vaultResolved = personas.get('cookie_vault')
    assert.ok(vaultResolved?.secretPath, 'Persona Vault cookie credential must have host secretPath')
    assert.equal(statSync(vaultResolved.secretPath).mode & 0o077, 0, 'Persona Vault cookie file must be 0600')

    const broker = new RequestBroker({ rejectUnauthorized: false })
    const sig = AbortSignal.timeout(30_000)
    let allowOrigin1 = true
    const allowedOrigins = new Set([server1.origin, server2.origin])
    const grant = makeLabGrant(server1.origin, {
      tier: 2,
      scopeRevision: 1,
      personas,
      canRead: origin => (origin === server1.origin ? allowOrigin1 : allowedOrigins.has(origin)),
    })

    // 1. Session handle BVA (/^[a-z0-9_-]{1,32}$/)
    for (const invalidSession of ['', '../bad', 'a'.repeat(33), 'JAR_UPPER', 'jar space', 'jar;1']) {
      await assert.rejects(
        broker.executeHttp(asBrokerRequest({
          origin: server1.origin,
          method: 'GET',
          pathAndQuery: '/echo-cookie',
          session: invalidSession,
        }), grant, sig),
        BrokerDenied,
        `Invalid session handle "${invalidSession}" must be rejected with BrokerDenied`,
      )
    }
    for (const validSession of ['a', 'a'.repeat(32)]) {
      const okEx = await broker.executeHttp(asBrokerRequest({
        origin: server1.origin,
        method: 'GET',
        pathAndQuery: '/echo-cookie',
        session: validSession,
        runId,
        assignmentId,
      }), grant, sig)
      assert.equal(okEx.status, 200, `Valid boundary session handle "${validSession}" must succeed`)
    }

    // 2. Populate jar-a on origin1 via /set-cookie (scoped to runId + assignmentId)
    const setEx = await broker.executeHttp(asBrokerRequest({
      origin: server1.origin,
      method: 'GET',
      pathAndQuery: '/set-cookie',
      session: 'jar-a',
      runId,
      assignmentId,
    }), grant, sig)

    // Verify cookie is stored in jar-a and replayed on origin1 with same (runId, assignmentId, session='jar-a')
    const echoJarA = await broker.executeHttp(asBrokerRequest({
      origin: server1.origin,
      method: 'GET',
      pathAndQuery: '/echo-cookie',
      session: 'jar-a',
      runId,
      assignmentId,
    }), grant, sig)
    assert.equal(JSON.parse(echoJarA.body).hasSid, true, 'jar-a must send stored cookie back to same (runId, assignmentId, origin)')
    assert.equal(origin1SeenCookies.at(-1)?.cookie?.includes(secretCookie), true)

    // 3. Jar-b, omitted session, origin2, cross-assignment, and cross-run must NOT receive jar-a cookie
    const echoJarB = await broker.executeHttp(asBrokerRequest({
      origin: server1.origin,
      method: 'GET',
      pathAndQuery: '/echo-cookie',
      session: 'jar-b',
      runId,
      assignmentId,
    }), grant, sig)
    assert.equal(JSON.parse(echoJarB.body).hasSid, false, 'jar-b must be isolated from jar-a')
    assert.equal(origin1SeenCookies.at(-1)?.cookie?.includes(secretCookie) ?? false, false)

    const echoNoSession = await broker.executeHttp(asBrokerRequest({
      origin: server1.origin,
      method: 'GET',
      pathAndQuery: '/echo-cookie',
      runId,
      assignmentId,
    }), grant, sig)
    assert.equal(JSON.parse(echoNoSession.body).hasSid, false, 'session-less request must not use jar-a')
    assert.equal(origin1SeenCookies.at(-1)?.cookie?.includes(secretCookie) ?? false, false)

    const echoCrossAssign = await broker.executeHttp(asBrokerRequest({
      origin: server1.origin,
      method: 'GET',
      pathAndQuery: '/echo-cookie',
      session: 'jar-a',
      runId,
      assignmentId: randomUUID(),
    }), grant, sig)
    assert.equal(JSON.parse(echoCrossAssign.body).hasSid, false, 'jar-a must not leak across different assignmentId')
    assert.equal(origin1SeenCookies.at(-1)?.cookie?.includes(secretCookie) ?? false, false)

    const echoCrossRun = await broker.executeHttp(asBrokerRequest({
      origin: server1.origin,
      method: 'GET',
      pathAndQuery: '/echo-cookie',
      session: 'jar-a',
      runId: randomUUID(),
      assignmentId,
    }), grant, sig)
    assert.equal(JSON.parse(echoCrossRun.body).hasSid, false, 'jar-a must not leak across different runId')
    assert.equal(origin1SeenCookies.at(-1)?.cookie?.includes(secretCookie) ?? false, false)

    await broker.executeHttp(asBrokerRequest({
      origin: server2.origin,
      method: 'GET',
      pathAndQuery: '/echo-cookie',
      session: 'jar-a',
      runId,
      assignmentId,
    }), grant, sig)
    assert.equal(origin2SeenCookies[0]?.cookie?.includes(secretCookie) ?? false, false, 'jar-a cookies must not cross origins')

    // 3b. Path=/admin, Secure over http://, and 0600 Persona Vault cookie precedence
    await broker.executeHttp(asBrokerRequest({
      origin: server1.origin,
      method: 'GET',
      pathAndQuery: '/set-scoped-cookies',
      session: 'jar-scoped',
      runId,
      assignmentId,
    }), grant, sig)
    const adminEcho = JSON.parse(
      (await broker.executeHttp(asBrokerRequest({
        origin: server1.origin,
        method: 'GET',
        pathAndQuery: '/admin/echo',
        session: 'jar-scoped',
        runId,
        assignmentId,
      }), grant, sig)).body,
    ) as { hasAdmin: boolean; hasSec: boolean }
    assert.equal(adminEcho.hasAdmin, true, 'Path=/admin cookie must be sent to /admin/echo')
    assert.equal(adminEcho.hasSec, false, 'Secure cookie must NOT be sent over plain http://127.0.0.1')

    const publicEcho = JSON.parse(
      (await broker.executeHttp(asBrokerRequest({
        origin: server1.origin,
        method: 'GET',
        pathAndQuery: '/public/echo',
        session: 'jar-scoped',
        runId,
        assignmentId,
      }), grant, sig)).body,
    ) as { hasAdmin: boolean; hasSec: boolean }
    assert.equal(publicEcho.hasAdmin, false, 'Path=/admin cookie must NOT be sent to /public/echo')
    assert.equal(publicEcho.hasSec, false, 'Secure cookie must NOT be sent over plain http://127.0.0.1 to /public/echo')

    await broker.executeHttp(asBrokerRequest({
      origin: server1.origin,
      method: 'GET',
      pathAndQuery: '/set-vault-collision',
      persona: 'cookie_vault',
      session: 'jar-vault',
      runId,
      assignmentId,
    }), grant, sig)
    const echoVaultEx = await broker.executeHttp(asBrokerRequest({
      origin: server1.origin,
      method: 'GET',
      pathAndQuery: '/echo-cookie',
      persona: 'cookie_vault',
      session: 'jar-vault',
      runId,
      assignmentId,
    }), grant, sig)
    const echoVaultBody = JSON.parse(echoVaultEx.body) as {
      hasVaultAuth: boolean
      hasVaultOverwrite: boolean
      hasCsrf: boolean
    }
    assert.equal(echoVaultBody.hasVaultAuth, true, '0600 Persona Vault cookie must take precedence over session jar')
    assert.equal(echoVaultBody.hasVaultOverwrite, false, 'Session jar Set-Cookie must never overwrite 0600 Persona Vault cookie')
    assert.equal(echoVaultBody.hasCsrf, true, 'Non-colliding session jar cookies (csrf_jar) must still merge alongside Persona Vault cookie')
    assert.ok(!JSON.stringify(echoVaultEx).includes('VAULT_AUTH_SECRET_999'), 'BrokerExchangeResult must scrub Persona Vault cookie secret')

    // 4. Zero raw cookies in BrokerExchangeResult & SQLite broker_exchanges
    for (const ex of [setEx, echoJarA, echoVaultEx]) {
      const exRecord = storage.recordExchange({
        runId,
        assignmentId,
        scopeRevision: 1,
        origin: ex.origin,
        finalOrigin: ex.finalOrigin,
        redirectOrigins: ex.redirectOrigins,
        method: ex.method,
        pathAndQuery: ex.pathAndQuery,
        personaHandle: ex.personaHandle,
        status: ex.status,
        mediaType: ex.mediaType,
        reqHeaders: ex.reqHeaders,
        respHeaders: ex.respHeaders,
        body: ex.body,
        durationMs: ex.durationMs,
      })
      assert.ok(!JSON.stringify(ex).includes(secretCookie), 'BrokerExchangeResult must never expose raw jar cookie')
      assert.ok(!JSON.stringify(exRecord).includes(secretCookie), 'Recorded exchange must never expose raw jar cookie')
      assert.ok(!JSON.stringify(exRecord).includes('VAULT_AUTH_SECRET_999'), 'Recorded exchange must never expose Persona Vault cookie')
    }
    const dbRows = storage.client.prepare(
      'SELECT req_headers, resp_headers, body_preview FROM broker_exchanges WHERE run_id = ?',
    ).all(runId)
    assert.ok(!JSON.stringify(dbRows).includes(secretCookie), 'SQLite broker_exchanges must contain 0 raw jar cookies')
    assert.ok(!JSON.stringify(dbRows).includes('VAULT_AUTH_SECRET_999'), 'SQLite broker_exchanges must contain 0 Persona Vault cookie secrets')
    const eventsRows = storage.client.prepare('SELECT message, detail FROM events WHERE run_id = ?').all(runId)
    assert.ok(!JSON.stringify(eventsRows).includes(secretCookie), 'SSE events table must contain 0 raw jar cookies')

    // 5. Control vs Probe isolation in ReplayVerifier http_chain (both negative control & positive probe retention)
    const backend = new LinuxWorkerBackend()
    const chainRes = await verifyReplaySpec({
      spec: {
        version: 1,
        kind: 'http_chain',
        origin: server1.origin,
        title: 'Verify control vs probe session jar isolation',
        category: 'auth-session',
        cwe: 'CWE-384',
        severity: 'medium',
        severityRationale: 'Session isolation check',
        impact: 'Cookie isolation',
        remediation: 'Isolate control and probe jars',
        recheckInstructions: 'Replay isolation test',
        steps: [
          {
            id: 'probe_login',
            role: 'probe',
            description: 'Probe receives Set-Cookie',
            request: { origin: server1.origin, method: 'GET', pathAndQuery: '/set-cookie', session: 'shared-name' },
          },
          {
            id: 'control_check',
            role: 'control',
            description: 'Control must not inherit probe session jar',
            request: { origin: server1.origin, method: 'GET', pathAndQuery: '/echo-cookie', session: 'shared-name' },
          },
          {
            id: 'probe_check',
            role: 'probe',
            description: 'Probe retains its own session jar',
            request: { origin: server1.origin, method: 'GET', pathAndQuery: '/echo-cookie', session: 'shared-name' },
          },
        ],
        assertionsJq: '{ controlPassed: (.steps.control_check.json.hasSid == false), confirmed: (.steps.control_check.json.hasSid == false and .steps.probe_check.json.hasSid == true), observed: ("ctrl=" + (.steps.control_check.json.hasSid | tostring) + ",probe=" + (.steps.probe_check.json.hasSid | tostring)), expected: "ctrl=false,probe=true" }',
      } as unknown,
      broker,
      backend,
      grant,
      signal: AbortSignal.timeout(60_000),
    })
    assert.equal(chainRes.verdict, 'confirmed', `control must be isolated while probe retains jar: ${JSON.stringify(chainRes.outcome)}`)
    assert.ok(!JSON.stringify(chainRes).includes(secretCookie), 'ReplayVerificationResult must scrub jar cookie')

    // 6. Scope revocation purges session jar cookies for revoked origin (and scopeRevision 1 -> 2)
    const v4Broker = broker as unknown as V4BrokerContract
    assert.ok(
      typeof v4Broker.revokeOrigin === 'function' || typeof v4Broker.revokeScope === 'function',
      'RequestBroker v4 must expose revokeOrigin or revokeScope',
    )
    allowOrigin1 = false
    const revGrant = makeLabGrant(server1.origin, {
      tier: 2,
      scopeRevision: 2,
      personas,
      canRead: origin => (origin === server1.origin ? allowOrigin1 : allowedOrigins.has(origin)),
    })
    if (typeof v4Broker.revokeOrigin === 'function') {
      v4Broker.revokeOrigin(server1.origin)
    }
    if (typeof v4Broker.revokeScope === 'function') {
      v4Broker.revokeScope(2)
    }
    await assert.rejects(
      broker.executeHttp(asBrokerRequest({
        origin: server1.origin,
        method: 'GET',
        pathAndQuery: '/echo-cookie',
        session: 'jar-a',
        runId,
        assignmentId,
      }), revGrant, sig),
      BrokerDenied,
      'Revoked origin / scopeRevision advance (1 -> 2) must reject executeHttp with BrokerDenied',
    )
    // Even if origin1 is later re-enabled, old jar-a cookies must have been purged on revocation
    allowOrigin1 = true
    const afterReallow = await broker.executeHttp(asBrokerRequest({
      origin: server1.origin,
      method: 'GET',
      pathAndQuery: '/echo-cookie',
      session: 'jar-a',
      runId,
      assignmentId,
    }), revGrant, sig)
    assert.equal(JSON.parse(afterReallow.body).hasSid, false, 'Revoked origin jar cookies must be purged and never reappear')
  })
})

// ============================================================================
// V4-B2: authMutation redaction (all 7 kinds + wire verification + zero leak)
// ============================================================================

test('V4-B2 authMutation redaction: all 7 kinds mutate on the wire, reject missing persona/tier<2, and leak 0 original or mutated JWT bytes', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v4-b2-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const publicJwk = publicKey.export({ format: 'jwk' })
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }) as string
  const wireTokens: Array<{ testCase: string; authHeader: string }> = []
  let jwksFetchCount = 0

  const canaryBroker = new CanaryBroker()
  t.after(() => canaryBroker.stopListener())
  const canaryInfo = await canaryBroker.startListener({ host: '127.0.0.1', port: 0 })
  assert.ok(canaryInfo.effectiveBaseUrl, 'CanaryBroker must expose effectiveBaseUrl')

  const server = await startLoopbackServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/.well-known/jwks.json') {
      jwksFetchCount += 1
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({
        keys: [{ ...publicJwk, kid: 'test-rsa-1', use: 'sig', alg: 'RS256' }],
      }))
      return
    }
    const auth = req.headers.authorization ?? ''
    const tc = String(req.headers['x-test-case'] ?? 'unknown')
    wireTokens.push({ testCase: tc, authHeader: auth })
    // Deliberately echo raw Authorization back in body to prove dynamic redact() scrubs mutated JWTs from responses too!
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({
      ok: true,
      echoedAuthorization: auth,
    }))
  })
  t.after(() => server.close())

  const originalJwt = makeSignedJwt(
    { alg: 'RS256', typ: 'JWT', kid: 'test-rsa-1' },
    { sub: 'user-100', role: 'viewer', exp: Math.floor(Date.now() / 1000) + 3600 },
    'persona-original-hmac-secret',
  )

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const { storage, projectId, runId, assignmentId } = setupProjectAndRun(dir, 'local-lab', server.origin, 2)
    t.after(() => storage.close())

    const { id: personaId } = createProjectPersona(storage, {
      requestId: randomUUID(),
      projectId,
      handle: 'persona_jwt',
      roleLabel: 'Viewer',
      originAllowlist: [server.origin],
      authKind: 'bearer',
      secret: originalJwt,
      canaryMarkers: [],
    })
    const personas = resolveRunPersonas(storage, projectId, [personaId])
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const sig = AbortSignal.timeout(30_000)
    const grant = makeLabGrant(server.origin, { tier: 2, personas })

    // Rejection when persona omitted, Tier < 2, or public Tier-2 claim_swap
    await assert.rejects(
      broker.executeHttp(asBrokerRequest({
        origin: server.origin,
        method: 'GET',
        pathAndQuery: '/auth-check',
        authMutation: { kind: 'alg_none' },
      }), grant, sig),
      BrokerDenied,
      'authMutation without persona must fail with BrokerDenied',
    )
    await assert.rejects(
      broker.executeHttp(asBrokerRequest({
        origin: server.origin,
        method: 'GET',
        pathAndQuery: '/auth-check',
        persona: 'persona_jwt',
        authMutation: { kind: 'alg_none' },
      }), makeLabGrant(server.origin, { tier: 1, personas }), sig),
      BrokerDenied,
      'authMutation at Tier < 2 must fail with BrokerDenied',
    )
    await assert.rejects(
      broker.executeHttp(asBrokerRequest({
        origin: server.origin,
        method: 'GET',
        pathAndQuery: '/auth-check',
        persona: 'persona_jwt',
        authMutation: { kind: 'claim_swap', claims: { role: 'admin' } },
      }), makeLabGrant(server.origin, { tier: 2, allowLocalLab: false, personas }), sig),
      BrokerDenied,
      'claim_swap on public Tier-2 (allowLocalLab: false) must fail with BrokerDenied',
    )

    const jkuCanary = canaryBroker.mintCanary(runId, 'jwt-jku-canary', server.origin, { storage })
    const x5uCanary = canaryBroker.mintCanary(runId, 'jwt-x5u-canary', server.origin, { storage })

    const mutations: Array<{ name: string; mutation: V4AuthMutation }> = [
      { name: 'alg_none', mutation: { kind: 'alg_none' } },
      { name: 'strip_signature', mutation: { kind: 'strip_signature' } },
      { name: 'expired_replay', mutation: { kind: 'expired_replay', skewSeconds: 7200 } },
      { name: 'rs256_to_hs256_jwks', mutation: { kind: 'rs256_to_hs256_jwks', jwksUrl: `${server.origin}/.well-known/jwks.json` } },
      { name: 'kid_inject', mutation: { kind: 'kid_inject', value: "1' OR '1'='1" } },
      { name: 'jku_x5u_canary', mutation: { kind: 'jku_x5u_canary', header: 'jku', value: jkuCanary.httpUrl } },
      { name: 'x5u_canary', mutation: { kind: 'jku_x5u_canary', header: 'x5u', value: x5uCanary.httpUrl } },
      { name: 'claim_swap', mutation: { kind: 'claim_swap', claims: { role: 'admin', sub: 'admin-1' } } },
    ]

    const observedMutatedJwts: string[] = []
    for (const { name, mutation } of mutations) {
      const ex = await broker.executeHttp(asBrokerRequest({
        origin: server.origin,
        method: 'GET',
        pathAndQuery: '/auth-check',
        headers: { 'x-test-case': name },
        persona: 'persona_jwt',
        authMutation: mutation,
      }), grant, sig)

      const wireEntry = wireTokens.find(w => w.testCase === name)
      assert.ok(wireEntry && wireEntry.authHeader.startsWith('Bearer '), `Wire request missing Bearer for ${name}`)
      const wireJwt = wireEntry.authHeader.slice('Bearer '.length).trim()
      assert.notEqual(wireJwt, originalJwt, `authMutation(${name}) must mutate the outbound JWT`)
      observedMutatedJwts.push(wireJwt)

      const parts = wireJwt.split('.')
      assert.equal(parts.length, 3, `Mutated JWT for ${name} must remain 3-part JWS format`)
      const decodedHeader = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as Record<string, unknown>
      const decodedPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Record<string, unknown>

      if (name === 'alg_none') assert.equal(String(decodedHeader.alg).toLowerCase(), 'none')
      if (name === 'strip_signature') assert.equal(parts[2], '')
      if (name === 'expired_replay') assert.ok(Number(decodedPayload.exp) < Math.floor(Date.now() / 1000))
      if (name === 'rs256_to_hs256_jwks') {
        assert.ok(jwksFetchCount >= 1, 'rs256_to_hs256_jwks must fetch JWKS from jwksUrl')
        assert.equal(decodedHeader.alg, 'HS256')
        const expectedSig = createHmac('sha256', publicPem).update(`${parts[0]}.${parts[1]}`).digest('base64url')
        assert.equal(parts[2], expectedSig, 'rs256_to_hs256_jwks signature must match HMAC-SHA256 over fetched publicKey PEM')
      }
      if (name === 'kid_inject') assert.equal(decodedHeader.kid, "1' OR '1'='1")
      if (name === 'jku_x5u_canary') {
        assert.ok(
          typeof decodedHeader.jku === 'string' &&
            decodedHeader.jku.startsWith(canaryInfo.effectiveBaseUrl!) &&
            /\/c\/kovo-canary-[a-f0-9]{24}/.test(decodedHeader.jku),
          'jku header must start with CanaryBroker effectiveBaseUrl and carry a minted canary token',
        )
      }
      if (name === 'x5u_canary') {
        assert.ok(
          typeof decodedHeader.x5u === 'string' &&
            decodedHeader.x5u.startsWith(canaryInfo.effectiveBaseUrl!) &&
            /\/c\/kovo-canary-[a-f0-9]{24}/.test(decodedHeader.x5u),
          'x5u header must start with CanaryBroker effectiveBaseUrl and carry a minted canary token',
        )
      }
      if (name === 'claim_swap') assert.equal(decodedPayload.role, 'admin')

      // Persist exchange and verify neither original nor mutated JWT appears anywhere
      storage.recordExchange({
        runId,
        assignmentId,
        scopeRevision: 1,
        origin: ex.origin,
        finalOrigin: ex.finalOrigin,
        redirectOrigins: ex.redirectOrigins,
        method: ex.method,
        pathAndQuery: ex.pathAndQuery,
        personaHandle: ex.personaHandle,
        status: ex.status,
        mediaType: ex.mediaType,
        reqHeaders: ex.reqHeaders,
        respHeaders: ex.respHeaders,
        body: ex.body,
        durationMs: ex.durationMs,
      })
      const serializedEx = JSON.stringify(ex)
      assert.ok(!serializedEx.includes(originalJwt), `Original JWT leaked in BrokerExchangeResult (${name})`)
      assert.ok(!serializedEx.includes(wireJwt), `Mutated JWT leaked in BrokerExchangeResult (${name})`)
    }

    // Verify SQLite broker_exchanges contains zero original or mutated JWT bytes
    const dbSerialized = JSON.stringify(
      storage.client.prepare('SELECT req_headers, resp_headers, body_preview FROM broker_exchanges WHERE run_id = ?').all(runId),
    )
    assert.ok(!dbSerialized.includes(originalJwt), 'Original JWT leaked in SQLite broker_exchanges')
    for (const mut of observedMutatedJwts) {
      assert.ok(!dbSerialized.includes(mut), 'Mutated JWT leaked in SQLite broker_exchanges')
    }

    // Verify InlineVerifyFeedback scrubs both original and mutated JWTs if verifyReplaySpecInline is exercised
    const rvMod = (await import('../src/server/replay-verifier.ts')) as Record<string, unknown>
    const verifyInline = assertExportFn<(...args: unknown[]) => Promise<V4InlineVerifyResult>>(
      rvMod,
      'verifyReplaySpecInline',
      'src/server/replay-verifier.ts',
    )
    const inlineRes = await verifyInline({
      runId,
      assignmentId,
      attemptCount: 1,
      spec: {
        version: 1,
        kind: 'http_chain',
        origin: server.origin,
        title: 'Auth mutation redaction check',
        category: 'auth-session',
        cwe: 'CWE-347',
        severity: 'high',
        severityRationale: 'JWT alg_none test',
        impact: 'Auth bypass',
        remediation: 'Enforce alg allowlist',
        recheckInstructions: 'Replay with alg_none',
        steps: [
          { id: 'control', role: 'control', description: 'Valid token', request: { origin: server.origin, method: 'GET', pathAndQuery: '/auth-check', persona: 'persona_jwt' } },
          { id: 'probe', role: 'probe', description: 'Mutated token', request: { origin: server.origin, method: 'GET', pathAndQuery: '/auth-check', persona: 'persona_jwt', authMutation: { kind: 'alg_none' } } },
        ],
        assertionsJq: '{ controlPassed: (.steps.control.status == 200), confirmed: false, observed: .steps.probe.bodyPreview, expected: "redacted" }',
      },
      broker,
      backend: new LinuxWorkerBackend(),
      grant,
      signal: sig,
      storage,
    })
    assert.equal(inlineRes.replay.verdict, 'dismissed')
    assert.equal(inlineRes.feedback.verdict, 'dismissed')
    assert.equal(inlineRes.feedback.stepStatuses.length, 2)
    const inlineResStr = JSON.stringify(inlineRes)
    assert.ok(!inlineResStr.includes(originalJwt), 'InlineVerify result leaked original JWT')
    for (const mut of observedMutatedJwts) {
      assert.ok(!inlineResStr.includes(mut), 'InlineVerify result leaked mutated JWT')
    }
  })
})

// ============================================================================
// V4-B3: Mandatory ?_gcb= cache-buster enforcement & cache_differential
// ============================================================================

test('V4-B3 cache-buster ?_gcb= enforcement: probeDifferential auto-appends _gcb, Broker/Zod rejects missing/malformed/reused _gcb, and clean unauth HIT confirms', async t => {
  const observedUrls: Array<{ url: string; xfh: string | undefined }> = []
  const poisonedCache = new Map<string, string>()

  const cacheServer = await startLoopbackServer((req, res) => {
    const reqUrl = req.url ?? '/'
    const xfh = typeof req.headers['x-forwarded-host'] === 'string' ? req.headers['x-forwarded-host'] : undefined
    observedUrls.push({ url: reqUrl, xfh })

    if (xfh) {
      const poisonedBody = `CACHED_HOST=${xfh}`
      poisonedCache.set(reqUrl, poisonedBody)
      res.writeHead(200, { 'Content-Type': 'text/html', 'X-Cache': 'MISS' }).end(poisonedBody)
      return
    }
    const cached = poisonedCache.get(reqUrl)
    if (cached) {
      res.writeHead(200, { 'Content-Type': 'text/html', 'X-Cache': 'HIT', 'Age': '5' }).end(cached)
      return
    }
    res.writeHead(200, { 'Content-Type': 'text/html', 'X-Cache': 'MISS' }).end('CACHED_HOST=clean-origin')
  })
  t.after(() => cacheServer.close())

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const grant = makeLabGrant(cacheServer.origin, { tier: 2 })
    const sig = AbortSignal.timeout(30_000)

    // 1. probeDifferential('cache_poison_deception') must auto-append valid ?_gcb= on every wire request
    const probeReq = {
      probeClass: 'cache_poison_deception',
      origin: cacheServer.origin,
      pathAndQuery: '/landing',
    } as unknown as ProbeDifferentialRequest
    const diff = await probeDifferential(probeReq, broker, grant, undefined, sig)
    assert.ok(diff.requestsSent > 0, 'cache_poison_deception must issue wire requests')
    for (const entry of observedUrls) {
      const parsed = new URL(entry.url, cacheServer.origin)
      const gcb = parsed.searchParams.get('_gcb')
      assert.ok(gcb && GCB_REGEX.test(gcb), `Every cache probe request must include valid ?_gcb=, got: ${entry.url}`)
    }

    // 1b. Query-string (?tab=1&sort=asc) preservation when appending ?_gcb=
    observedUrls.length = 0
    const diffWithQuery = await probeDifferential({
      probeClass: 'cache_poison_deception',
      origin: cacheServer.origin,
      pathAndQuery: '/landing?tab=1&sort=asc',
    } as unknown as ProbeDifferentialRequest, broker, grant, undefined, sig)
    assert.ok(diffWithQuery.requestsSent > 0, 'cache_poison_deception with query string must issue wire requests')
    for (const entry of observedUrls) {
      const parsed = new URL(entry.url, cacheServer.origin)
      assert.equal(parsed.searchParams.get('tab'), '1', `Query param tab=1 must be preserved, got: ${entry.url}`)
      assert.equal(parsed.searchParams.get('sort'), 'asc', `Query param sort=asc must be preserved, got: ${entry.url}`)
      const gcb = parsed.searchParams.get('_gcb')
      assert.ok(gcb && GCB_REGEX.test(gcb), `Every cache probe request must include valid ?_gcb=, got: ${entry.url}`)
    }

    // 2. Reject missing/malformed/reused _gcb in RequestBroker & Zod schema & ReplayVerifier
    await assert.rejects(
      broker.executeHttp(asBrokerRequest({
        origin: cacheServer.origin,
        method: 'GET',
        pathAndQuery: '/landing',
        probeClass: 'cache_poison_deception',
      }), grant, sig),
      BrokerDenied,
      'Broker must reject cache_poison_deception request missing ?_gcb=',
    )
    await assert.rejects(
      broker.executeHttp(asBrokerRequest({
        origin: cacheServer.origin,
        method: 'GET',
        pathAndQuery: '/landing?_gcb=123',
        probeClass: 'cache_poison_deception',
      }), grant, sig),
      BrokerDenied,
      'Broker must reject malformed short ?_gcb=',
    )

    const missingGcbSpec = declarativeReplaySpecSchema.safeParse({
      version: 1,
      kind: 'cache_differential',
      origin: cacheServer.origin,
      targetOrigin: cacheServer.origin,
      title: 'Missing _gcb cache differential',
      category: 'misconfig-exposure',
      cwe: 'CWE-444',
      severity: 'high',
      severityRationale: 'Unkeyed X-Forwarded-Host cached',
      impact: 'Cache poisoning',
      remediation: 'Vary or strip X-Forwarded-Host',
      recheckInstructions: 'Replay with fresh _gcb',
      controlPath: '/landing',
      probePath: '/landing',
      poisonHeaders: { 'X-Forwarded-Host': 'evil.invalid' },
      assertionsJq: '{ controlPassed: true, confirmed: true, observed: "hit", expected: "clean" }',
    } as unknown)
    assert.equal(missingGcbSpec.success, false, 'cache_differential schema must reject specs without ?_gcb=')

    const reusedGcb = 'abcdef0123456789abcdef0123456789'
    const reusedGcbSpec = declarativeReplaySpecSchema.safeParse({
      version: 1,
      kind: 'cache_differential',
      origin: cacheServer.origin,
      targetOrigin: cacheServer.origin,
      title: 'Reused _gcb across control and probe',
      category: 'misconfig-exposure',
      cwe: 'CWE-444',
      severity: 'high',
      severityRationale: 'Unkeyed X-Forwarded-Host cached',
      impact: 'Cache poisoning',
      remediation: 'Vary or strip X-Forwarded-Host',
      recheckInstructions: 'Replay with distinct _gcb',
      controlPath: `/landing?_gcb=${reusedGcb}`,
      probePath: `/landing?_gcb=${reusedGcb}`,
      poisonHeaders: { 'X-Forwarded-Host': 'evil.invalid' },
      assertionsJq: '{ controlPassed: true, confirmed: true, observed: "hit", expected: "clean" }',
    } as unknown)
    if (reusedGcbSpec.success) {
      const reusedResult = await verifyReplaySpec({
        spec: reusedGcbSpec.data,
        broker,
        backend: new LinuxWorkerBackend(),
        grant,
        signal: AbortSignal.timeout(60_000),
      })
      assert.notEqual(reusedResult.verdict, 'confirmed', 'Reused _gcb across control & probe must never confirm')
    } else {
      assert.match(reusedGcbSpec.error.message, /_gcb|cache.?buster|distinct|unique/i)
    }

    // Direct RequestBroker _gcb reuse rejection check
    await broker.executeHttp(asBrokerRequest({
      origin: cacheServer.origin,
      method: 'GET',
      pathAndQuery: `/landing?_gcb=${reusedGcb}`,
      probeClass: 'cache_poison_deception',
    }), grant, sig)
    await assert.rejects(
      broker.executeHttp(asBrokerRequest({
        origin: cacheServer.origin,
        method: 'GET',
        pathAndQuery: `/landing?_gcb=${reusedGcb}`,
        probeClass: 'cache_poison_deception',
      }), grant, sig),
      BrokerDenied,
      'RequestBroker must reject reusing the same _gcb across cache_poison_deception requests',
    )

    // 3. Valid cache_differential with clean unauthenticated control & matching probe _gcb confirms
    const validRes = await verifyReplaySpec({
      spec: {
        version: 1,
        kind: 'cache_differential',
        origin: cacheServer.origin,
        targetOrigin: cacheServer.origin,
        title: 'X-Forwarded-Host web cache poisoning',
        category: 'misconfig-exposure',
        cwe: 'CWE-444',
        severity: 'high',
        severityRationale: 'Unkeyed X-Forwarded-Host poisoned response served to clean unauth request.',
        impact: 'Attacker can poison cached HTML for other users.',
        remediation: 'Include host header in cache key or ignore X-Forwarded-Host.',
        recheckInstructions: 'Re-run cache_differential check.',
        controlPath: '/landing?_gcb={{control_gcb}}',
        probePath: '/landing?_gcb={{probe_gcb}}',
        poisonHeaders: { 'X-Forwarded-Host': 'poison.kovo.invalid' },
        assertionsJq: '{ controlPassed: (.control.status == 200 and (.control.body | contains("clean-origin"))), confirmed: (.verify.status == 200 and (.verify.headers["x-cache"] == "HIT") and (.verify.body | contains("poison.kovo.invalid"))), observed: .verify.bodyPreview, expected: "clean-origin without X-Cache HIT" }',
      } as unknown,
      broker,
      backend: new LinuxWorkerBackend(),
      grant,
      signal: AbortSignal.timeout(60_000),
    })
    assert.equal(validRes.verdict, 'confirmed', `Valid cache_differential must confirm: ${JSON.stringify(validRes.outcome)}`)
  })
})

// ============================================================================
// V4-B4: Tier-2 sandboxWriteAllowlist
// ============================================================================

test('V4-B4 Tier-2 sandboxWriteAllowlist: public defaults to [], allowlist permits safe JSON/form/GraphQL/Next-Action POST, still blocks DELETE/multipart/non-allowlist/destructive', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v4-b4-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  const receivedPosts: Array<{ path: string; contentType: string; nextAction: string | undefined; body: string }> = []
  const server = await startLoopbackServer((req, res, body) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    receivedPosts.push({
      path: url.pathname,
      contentType: String(req.headers['content-type'] ?? ''),
      nextAction: typeof req.headers['next-action'] === 'string' ? req.headers['next-action'] : undefined,
      body,
    })
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true, path: url.pathname }))
  })
  t.after(() => server.close())

  // 1. Public project defaults sandbox_write_allowlist to [] in SQLite
  const publicDir = join(dir, 'public-db')
  mkdirSync(publicDir)
  const publicStore = new Store(publicDir)
  t.after(() => publicStore.close())
  const parsedProj = newProject.safeParse({
    requestId: randomUUID(),
    name: 'Public Default Allowlist',
    seeds: ['https://allowlist-test.example'],
    environment: 'public',
  })
  assert.equal(parsedProj.success, true)
  const { id: pubProjectId } = publicStore.createProject(parsedProj.data)
  const allowCol = publicStore.client.prepare('SELECT sandbox_write_allowlist FROM projects WHERE id = ?').get(pubProjectId) as
    | { sandbox_write_allowlist: string | null }
    | undefined
  assert.ok(allowCol !== undefined, 'projects table must expose sandbox_write_allowlist column (v4 schema M1)')
  assert.deepEqual(JSON.parse(allowCol.sandbox_write_allowlist ?? 'null'), [], 'public project must default sandboxWriteAllowlist to []')

  // 2. RequestBroker Tier-2 allowlist behavior
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const sig = AbortSignal.timeout(30_000)

    // Without allowlist on Tier-2 (even with allowLocalLab: false style public grant or explicit empty allowlist):
    const emptyAllowGrant = makeLabGrant(server.origin, {
      tier: 2,
      sandboxWriteAllowlist: [],
    })
    await assert.rejects(
      broker.executeHttp({
        origin: server.origin,
        method: 'POST',
        pathAndQuery: '/api/search',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ q: 'hello' }),
      }, emptyAllowGrant, sig),
      BrokerDenied,
      'Tier-2 POST must be rejected when sandboxWriteAllowlist is []',
    )

    // With allowlist configured for /api/search, /graphql, and /actions:
    const allowGrant = makeLabGrant(server.origin, {
      tier: 2,
      sandboxWriteAllowlist: [
        { origin: server.origin, method: 'POST', pathPattern: '/api/search' },
        { origin: server.origin, method: 'POST', pathPattern: '/graphql' },
        { origin: server.origin, method: 'POST', pathPattern: '/actions*' },
      ],
    })

    // JSON POST -> allowed without HITL
    const jsonRes = await broker.executeHttp({
      origin: server.origin,
      method: 'POST',
      pathAndQuery: '/api/search',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'laptop' }),
    }, allowGrant, sig)
    assert.equal(jsonRes.status, 200)

    // Form-urlencoded POST -> allowed without HITL
    const formRes = await broker.executeHttp({
      origin: server.origin,
      method: 'POST',
      pathAndQuery: '/api/search',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'q=laptop&page=1',
    }, allowGrant, sig)
    assert.equal(formRes.status, 200)

    // GraphQL POST -> allowed without HITL
    const gqlRes = await broker.executeHttp({
      origin: server.origin,
      method: 'POST',
      pathAndQuery: '/graphql',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: '{ viewer { id } }' }),
    }, allowGrant, sig)
    assert.equal(gqlRes.status, 200)

    // Next-Action POST -> allowed without HITL
    const nextRes = await broker.executeHttp({
      origin: server.origin,
      method: 'POST',
      pathAndQuery: '/actions/search',
      headers: { 'Content-Type': 'text/plain;charset=UTF-8', 'Next-Action': '7f9a1234deadbeef' },
      body: JSON.stringify(['query']),
    }, allowGrant, sig)
    assert.equal(nextRes.status, 200)
    assert.equal(receivedPosts[3]?.nextAction, '7f9a1234deadbeef')

    // Still blocks DELETE, multipartParts, non-allowlisted paths, path-traversal, prefix-bypass, PUT/PATCH, cross-origin, and destructive payloads at Tier 2
    await assert.rejects(
      broker.executeHttp({
        origin: server.origin,
        method: 'DELETE',
        pathAndQuery: '/api/search',
      }, allowGrant, sig),
      BrokerDenied,
      'DELETE must remain blocked at Tier 2 even if path matches',
    )
    await assert.rejects(
      broker.executeHttp({
        origin: server.origin,
        method: 'POST',
        pathAndQuery: '/api/search',
        multipartParts: [{ name: 'file', filename: 'a.txt', contentType: 'text/plain', content: 'hi' }],
      }, allowGrant, sig),
      BrokerDenied,
      'multipartParts must remain blocked at Tier 2',
    )
    await assert.rejects(
      broker.executeHttp({
        origin: server.origin,
        method: 'POST',
        pathAndQuery: '/api/admin/nuke',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: true }),
      }, allowGrant, sig),
      BrokerDenied,
      'Non-allowlisted POST path must remain blocked at Tier 2',
    )
    await assert.rejects(
      broker.executeHttp({
        origin: server.origin,
        method: 'POST',
        pathAndQuery: '/api/search/../admin/nuke',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: true }),
      }, allowGrant, sig),
      BrokerDenied,
      'Path traversal from allowlisted prefix must remain blocked at Tier 2',
    )
    await assert.rejects(
      broker.executeHttp({
        origin: server.origin,
        method: 'POST',
        pathAndQuery: '/api/search-admin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: true }),
      }, allowGrant, sig),
      BrokerDenied,
      'Prefix-bypass /api/search-admin must remain blocked when only /api/search is allowlisted',
    )
    await assert.rejects(
      broker.executeHttp({
        origin: server.origin,
        method: 'PUT',
        pathAndQuery: '/api/search',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ q: 'hello' }),
      }, allowGrant, sig),
      BrokerDenied,
      'PUT must remain blocked when allowlist specifies POST',
    )
    await assert.rejects(
      broker.executeHttp({
        origin: server.origin,
        method: 'PATCH',
        pathAndQuery: '/api/search',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ q: 'hello' }),
      }, allowGrant, sig),
      BrokerDenied,
      'PATCH must remain blocked when allowlist specifies POST',
    )
    await assert.rejects(
      broker.executeHttp({
        origin: server.origin,
        method: 'POST',
        pathAndQuery: '/api/search',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ q: 'rm -rf / && DROP TABLE users' }),
      }, allowGrant, sig),
      BrokerDenied,
      'Destructive payload must remain blocked at Tier 2 even on allowlisted POST',
    )

    // Cross-origin allowlist isolation: allowlist scoped to server.origin must NOT permit POST to server2.origin
    const server2 = await startLoopbackServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true }))
    })
    t.after(() => server2.close())
    const multiOriginGrant = makeLabGrant(server.origin, {
      tier: 2,
      canRead: o => o === server.origin || o === server2.origin,
      sandboxWriteAllowlist: [{ origin: server.origin, method: 'POST', pathPattern: '/api/search' }],
    })
    await assert.rejects(
      broker.executeHttp({
        origin: server2.origin,
        method: 'POST',
        pathAndQuery: '/api/search',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ q: 'cross-origin' }),
      }, multiOriginGrant, sig),
      BrokerDenied,
      'sandboxWriteAllowlist scoped to server.origin must not permit POST to server2.origin',
    )
  })

  // 3. allowLocalLab: false staging check with sandboxWriteAllowlist
  const stagingOrigin = 'https://staging.example.invalid'
  const stagingBroker = new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async url => ({
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ok: true, path: url.pathname }),
    }),
  })
  const stagingGrant: V4Grant = {
    origin: stagingOrigin,
    tier: 2,
    maxRpsPerOrigin: 50,
    allowLocalLab: false,
    canRead: o => o === stagingOrigin,
    sandboxWriteAllowlist: [{ origin: stagingOrigin, method: 'POST', pathPattern: '/api/search' }],
    audit: () => {},
  }
  const stagingSig = AbortSignal.timeout(30_000)
  const stagingOk = await stagingBroker.executeHttp({
    origin: stagingOrigin,
    method: 'POST',
    pathAndQuery: '/api/search',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ q: 'staging' }),
  }, stagingGrant, stagingSig)
  assert.equal(stagingOk.status, 200, 'Tier-2 allowlisted POST must succeed on public/staging allowLocalLab: false')
  await assert.rejects(
    stagingBroker.executeHttp({
      origin: stagingOrigin,
      method: 'POST',
      pathAndQuery: '/api/other',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ q: 'staging' }),
    }, stagingGrant, stagingSig),
    BrokerDenied,
    'Non-allowlisted POST on allowLocalLab: false must fail with BrokerDenied',
  )
})

// ============================================================================
// V4-B5: LabRunner multi-service --internal isolation
// ============================================================================

test('V4-B5 LabRunner multi-service --internal isolation: rejects unsafe compose directives, enforces local-lab+env, verifies inhibit_ipv4/CapDrop/inter-service/seed/zero orphans', async t => {
  const root = mkdtempSync(join(tmpdir(), 'kovo-v4-b5-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))

  const repoDir = join(root, 'multi-lab')
  mkdirSync(repoDir, { recursive: true })
  writeFileSync(join(repoDir, 'sidecar.js'), [
    "const http = require('http')",
    "http.createServer((req, res) => {",
    "  if (req.url === '/health') return res.end('ok')",
    "  res.end('SIDECAR_OK')",
    "}).listen(9090, '0.0.0.0')",
    '',
  ].join('\n'))
  writeFileSync(join(repoDir, 'app.js'), [
    "const http = require('http')",
    "http.createServer(async (req, res) => {",
    "  if (req.url === '/health') return res.end('ok')",
    "  if (req.url === '/sidecar') {",
    "    try {",
    "      const r = await fetch('http://sidecar:9090/')",
    "      return res.end(await r.text())",
    "    } catch (e) { return res.end('ERR:' + e.message) }",
    "  }",
    "  res.end('APP_OK')",
    "}).listen(8080, '0.0.0.0')",
    '',
  ].join('\n'))
  writeFileSync(join(repoDir, 'seed.js'), [
    "fetch('http://sidecar:9090/').then(r => r.text()).then(body => {",
    "  if (body !== 'SIDECAR_OK') process.exit(2)",
    "  console.log(JSON.stringify({ personas: [{ handle: 'persona_a', authKind: 'bearer', secret: 'seed-tok-a' }, { handle: 'persona_b', authKind: 'bearer', secret: 'seed-tok-b' }] }))",
    '}).catch(err => { console.error(err); process.exit(1) })',
    '',
  ].join('\n'))
  writeFileSync(join(repoDir, 'docker-compose.yml'), [
    'services:',
    '  app:',
    '    image: node:24-bookworm-slim',
    '    command: node /app/app.js',
    '  sidecar:',
    '    image: node:24-bookworm-slim',
    '    command: node /app/sidecar.js',
    '',
  ].join('\n'))

  const runner = new LabRunner()
  t.after(() => runner.stopAll())

  // 1. Unsafe compose directives must be rejected before launching any container
  const unsafeComposeScenarios: Array<{ label: string; yaml: string }> = [
    { label: 'privileged', yaml: 'services:\n  app:\n    image: node:24-bookworm-slim\n    privileged: true\n' },
    { label: 'network_mode_host', yaml: 'services:\n  app:\n    image: node:24-bookworm-slim\n    network_mode: host\n' },
    { label: 'cap_add', yaml: 'services:\n  app:\n    image: node:24-bookworm-slim\n    cap_add:\n      - SYS_ADMIN\n' },
    { label: 'host_ports', yaml: 'services:\n  app:\n    image: node:24-bookworm-slim\n    ports:\n      - "8080:8080"\n' },
    { label: 'host_bind_mount', yaml: 'services:\n  app:\n    image: node:24-bookworm-slim\n    volumes:\n      - /etc:/host-etc\n' },
  ]

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    for (const bad of unsafeComposeScenarios) {
      const badRunId = randomUUID()
      const badCompose = `docker-compose.${bad.label}.yml`
      writeFileSync(join(repoDir, badCompose), bad.yaml)
      await assert.rejects(
        runner.startLabTarget({
          runId: badRunId,
          environment: 'local-lab',
          repoDir,
          labConfig: {
            enabled: true,
            dockerComposeFile: badCompose,
            internalPort: 8080,
            healthPath: '/health',
          } as V4LabConfig,
          signal: AbortSignal.timeout(30_000),
        }),
        /privileged|network_mode|cap_add|ports|volume|bind|forbidden|unsafe/i,
        `Unsafe compose directive "${bad.label}" must be rejected`,
      )
      const created = (await exec('docker', ['ps', '-aq', '--filter', `label=dev.kovo.run=${badRunId}`])).stdout.trim()
      assert.equal(created, '', `Rejected compose (${bad.label}) must spawn 0 containers`)
    }
  })

  // 2. Enforce environment === 'local-lab' AND KOVO_ALLOW_LOCAL_LAB=1 (including direct startLabTarget({ environment: 'public' }))
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: undefined }, () => {
    assert.throws(() => assertLocalLabAllowed('local-lab'), /KOVO_ALLOW_LOCAL_LAB/)
  })
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    assert.throws(() => assertLocalLabAllowed('public'), /forbidden/)
    await assert.rejects(
      runner.startLabTarget({
        runId: randomUUID(),
        environment: 'public',
        repoDir,
        labConfig: { enabled: true },
        signal: AbortSignal.timeout(30_000),
      }),
      /forbidden|public|local-lab/i,
      'startLabTarget must reject environment: public directly even with KOVO_ALLOW_LOCAL_LAB=1',
    )
  })

  // 3. Valid multi-service launch with seedCommand + host 0.0.0.0 bridge gateway check
  const runId = randomUUID()
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const handle = (await runner.startLabTarget({
      runId,
      environment: 'local-lab',
      repoDir,
      labConfig: {
        enabled: true,
        internalPort: 8080,
        healthPath: '/health',
        image: 'node:24-bookworm-slim',
        startCommand: 'node /app/app.js',
        seedCommand: 'node /app/seed.js',
        services: [
          { name: 'app', image: 'node:24-bookworm-slim', command: 'node /app/app.js', internalPort: 8080, healthPath: '/health' },
          { name: 'sidecar', image: 'node:24-bookworm-slim', command: 'node /app/sidecar.js', internalPort: 9090, healthPath: '/health' },
        ],
      } as V4LabConfig,
      signal: AbortSignal.timeout(120_000),
    })) as unknown as V4LabTargetHandle

    // Verify network is --internal + inhibit_ipv4=true
    const netInspect = JSON.parse((await exec('docker', ['network', 'inspect', handle.networkName])).stdout)[0]
    assert.equal(netInspect.Internal, true, 'Multi-service lab network must be --internal')
    assert.equal(
      netInspect.Options?.['com.docker.network.bridge.inhibit_ipv4'],
      'true',
      'Lab network must set com.docker.network.bridge.inhibit_ipv4=true',
    )

    // Verify all containers on this run have CapDrop: ALL, no-new-privileges, zero PortBindings
    const containerIds = (await exec('docker', ['ps', '-q', '--filter', `label=dev.kovo.run=${runId}`]))
      .stdout.trim().split(/\s+/).filter(Boolean)
    assert.ok(containerIds.length >= 2, `Expected >=2 containers (app + sidecar) for multi-service stack, got ${containerIds.length}`)

    for (const cid of containerIds) {
      const c = JSON.parse((await exec('docker', ['inspect', cid])).stdout)[0]
      assert.deepEqual(c.HostConfig.CapDrop, ['ALL'])
      assert.equal(c.HostConfig.Privileged, false)
      assert.ok((c.HostConfig.SecurityOpt ?? []).some((o: string) => /no-new-privileges/.test(o)))
      assert.equal(Object.keys(c.HostConfig.PortBindings ?? {}).length, 0, 'Lab containers must publish 0 host ports')
    }

    // Verify zero internet egress AND zero host bridge gateway reachability from inside container
    let hostListenerHits = 0
    const hostListener = createServer((_req, res) => {
      hostListenerHits += 1
      res.writeHead(200).end('HOST_REACHED')
    }).listen(0, '0.0.0.0')
    t.after(() => new Promise<void>(resolveClose => {
      hostListener.closeAllConnections()
      hostListener.close(() => resolveClose())
    }))
    await once(hostListener, 'listening')
    const hostAddr = hostListener.address()
    assert.ok(hostAddr && typeof hostAddr !== 'string', 'Host 0.0.0.0 listener must bind')

    let bridgeGateway = '172.17.0.1'
    try {
      const bridgeInspect = JSON.parse((await exec('docker', ['network', 'inspect', 'bridge'])).stdout)[0] as {
        IPAM?: { Config?: Array<{ Gateway?: string }> }
      }
      if (bridgeInspect?.IPAM?.Config?.[0]?.Gateway) {
        bridgeGateway = bridgeInspect.IPAM.Config[0].Gateway
      }
    } catch {
      /* fallback to default 172.17.0.1 */
    }

    const egress = await exec('docker', [
      'exec',
      handle.containerName,
      'node',
      '-e',
      [
        `Promise.all([`,
        `  fetch('http://1.1.1.1',{signal:AbortSignal.timeout(1500)}).then(()=>'NET_OK',()=>'NET_BLOCKED'),`,
        `  fetch('http://${bridgeGateway}:${hostAddr.port}',{signal:AbortSignal.timeout(1500)}).then(()=>'GATEWAY_OK',()=>'GATEWAY_BLOCKED'),`,
        `  fetch('http://host.docker.internal:${hostAddr.port}',{signal:AbortSignal.timeout(1500)}).then(()=>'HOST_DNS_OK',()=>'HOST_DNS_BLOCKED')`,
        `]).then(r=>console.log(r.join(',')))`,
      ].join(''),
    ])
    assert.match(egress.stdout, /NET_BLOCKED/)
    assert.match(egress.stdout, /GATEWAY_BLOCKED/)
    assert.match(egress.stdout, /HOST_DNS_BLOCKED/)
    assert.ok(!egress.stdout.includes('NET_OK') && !egress.stdout.includes('GATEWAY_OK') && !egress.stdout.includes('HOST_DNS_OK'))
    assert.equal(hostListenerHits, 0, 'Host 0.0.0.0 listener must receive 0 requests from --internal container')

    const sidecarBody = await (await fetch(`${handle.origin}/sidecar`)).text()
    assert.equal(sidecarBody, 'SIDECAR_OK', 'App container must reach sidecar over --internal network')

    assert.ok(
      Array.isArray(handle.seededPersonas) && handle.seededPersonas.length >= 2,
      'seedCommand must populate handle.seededPersonas',
    )
    assert.deepEqual(
      handle.seededPersonas.map(p => p.handle).sort(),
      ['persona_a', 'persona_b'],
      'seededPersonas handles must match seed.js output',
    )
    assert.ok(
      handle.seededPersonas.every(p => p.authKind === 'bearer'),
      'seededPersonas authKind must match seed.js output',
    )

    // Verify 0 orphan containers & networks after stopAll()
    await runner.stopAll()
    const leftContainers = (await exec('docker', ['ps', '-aq', '--filter', `label=dev.kovo.run=${runId}`])).stdout.trim()
    const leftNetworks = (await exec('docker', ['network', 'ls', '-q', '--filter', `name=${handle.networkName}`])).stdout.trim()
    assert.equal(leftContainers, '', 'stopAll() must leave 0 orphan lab containers')
    assert.equal(leftNetworks, '', 'stopAll() must leave 0 orphan lab networks')

    // 4. Valid dockerComposeFile multi-service launch + seedCommand + stopLabTarget cleanup
    const composeRunId = randomUUID()
    const composeHandle = (await runner.startLabTarget({
      runId: composeRunId,
      environment: 'local-lab',
      repoDir,
      labConfig: {
        enabled: true,
        dockerComposeFile: 'docker-compose.yml',
        internalPort: 8080,
        healthPath: '/health',
        seedCommand: 'node /app/seed.js',
      } as V4LabConfig,
      signal: AbortSignal.timeout(120_000),
    })) as unknown as V4LabTargetHandle

    const composeNetInspect = JSON.parse((await exec('docker', ['network', 'inspect', composeHandle.networkName])).stdout)[0]
    assert.equal(composeNetInspect.Internal, true, 'dockerComposeFile lab network must be --internal')
    const composeCids = (await exec('docker', ['ps', '-q', '--filter', `label=dev.kovo.run=${composeRunId}`]))
      .stdout.trim().split(/\s+/).filter(Boolean)
    assert.ok(composeCids.length >= 2, `Expected >=2 containers for dockerComposeFile stack, got ${composeCids.length}`)
    const composeSidecarBody = await (await fetch(`${composeHandle.origin}/sidecar`)).text()
    assert.equal(composeSidecarBody, 'SIDECAR_OK', 'dockerComposeFile app must reach sidecar over --internal network')
    assert.deepEqual(
      (composeHandle.seededPersonas ?? []).map(p => p.handle).sort(),
      ['persona_a', 'persona_b'],
      'dockerComposeFile seedCommand must populate seededPersonas',
    )
    await runner.stopLabTarget(composeRunId)
    const composeLeft = (await exec('docker', ['ps', '-aq', '--filter', `label=dev.kovo.run=${composeRunId}`])).stdout.trim()
    const composeNetLeft = (await exec('docker', ['network', 'ls', '-q', '--filter', `name=${composeHandle.networkName}`])).stdout.trim()
    assert.equal(composeLeft, '', 'stopLabTarget(composeRunId) must leave 0 orphan containers')
    assert.equal(composeNetLeft, '', 'stopLabTarget(composeRunId) must leave 0 orphan networks')
  })
})

// ============================================================================
// V4-B6: IAST secret masking, 64 KiB cap, public rejection & ReplayVerifier isolation
// ============================================================================

test('V4-B6 IAST telemetry: rejects public projects, masks secrets & caps at 64 KiB, and ReplayVerifier never reads /evidence/lab-telemetry/', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v4-b6-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  const benignServer = await startLoopbackServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ rows: ['static-item'], safe: true }))
  })
  t.after(() => benignServer.close())

  // 1. Public projects must reject iastEnabled: true
  const publicDir = join(dir, 'public-iast')
  mkdirSync(publicDir)
  const publicStore = new Store(publicDir)
  t.after(() => publicStore.close())
  const { id: pubProjectId } = publicStore.createProject({
    requestId: randomUUID(),
    name: 'Public IAST Denied',
    seeds: ['https://public-iast.example'],
    environment: 'public',
  })
  assert.throws(
    () =>
      publicStore.updateProjectLabConfig({
        requestId: randomUUID(),
        projectId: pubProjectId,
        labConfig: { enabled: false, healthPath: '/', iastEnabled: true } as unknown as DomainLabConfig,
      }),
    /forbidden|public|local-lab|iast/i,
    'Public project must reject iastEnabled: true',
  )

  // 2. local-lab IAST secret scrubbing + 64 KiB cap + ReplayVerifier isolation
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const labDir = join(dir, 'lab-iast')
    mkdirSync(labDir)
    const { storage, projectId, runId, assignmentId } = setupProjectAndRun(labDir, 'local-lab', benignServer.origin, 2)
    t.after(() => storage.close())

    const personaSecret = 'PERSONA_IAST_SECRET_TOKEN_987654'
    const { id: personaId } = createProjectPersona(storage, {
      requestId: randomUUID(),
      projectId,
      handle: 'persona_iast',
      roleLabel: 'User',
      originAllowlist: [benignServer.origin],
      authKind: 'bearer',
      secret: personaSecret,
      canaryMarkers: [],
    })
    const personas = resolveRunPersonas(storage, projectId, [personaId])
    const exchangeId = randomUUID()
    const telemetryDir = join(labDir, 'evidence', 'lab-telemetry')
    mkdirSync(telemetryDir, { recursive: true })

    // Load v4 IAST telemetry processor (must exist in M5 under src/server/)
    const labMod = (await import('../src/server/lab-runner.ts')) as Record<string, unknown>
    const sanitizeIast = assertExportFn<
      (input: {
        runId: string
        exchangeId: string
        traceId: string
        environment: string
        telemetryDir: string
        rawTelemetry: Record<string, unknown>
        secrets: Array<{ value: string; placeholder: string }>
        storage?: Store
      }) => { filePath: string; bytesWritten: number }
    >(labMod, 'ingestLabTelemetry', 'src/server/lab-runner.ts')

    const hugePayload = 'A'.repeat(120_000)
    const res = sanitizeIast({
      runId,
      exchangeId,
      traceId: exchangeId,
      environment: 'local-lab',
      telemetryDir,
      secrets: [
        { value: personaSecret, placeholder: '[persona:persona_iast:secret]' },
      ],
      rawTelemetry: {
        routesHit: ['/api/search'],
        newLinesCovered: 12,
        sinkEvents: [
          {
            sink: 'pg.query',
            sql: `SELECT * FROM users WHERE token='${personaSecret}' AND aws='${RAW_AWS}' AND stripe='${RAW_STRIPE}'`,
            stack: hugePayload,
          },
        ],
        exceptions: [{ message: `Leak ${personaSecret} ${RAW_AWS}`, stack: hugePayload }],
      },
      storage,
    })

    assert.ok(existsSync(res.filePath), 'Sanitized IAST telemetry file must be written')
    const stat = statSync(res.filePath)
    assert.ok(stat.size <= 65_536, `IAST telemetry artifact must be <= 65536 bytes, got ${stat.size}`)
    const fileText = readFileSync(res.filePath, 'utf8')
    assert.ok(!fileText.includes(personaSecret), 'IAST telemetry file must scrub persona secret')
    assert.ok(!fileText.includes(RAW_AWS), 'IAST telemetry file must automatically scrub AWS key via built-in patterns')
    assert.ok(!fileText.includes(RAW_STRIPE), 'IAST telemetry file must automatically scrub Stripe key via built-in patterns')

    const iastRows = storage.client.prepare('SELECT * FROM lab_telemetry WHERE run_id = ?').all(runId)
    const dbText = JSON.stringify(iastRows)
    assert.ok(iastRows.length >= 1, 'lab_telemetry table must persist sanitized telemetry metadata')
    assert.ok(!dbText.includes(personaSecret) && !dbText.includes(RAW_AWS) && !dbText.includes(RAW_STRIPE))

    // 2b. RequestBroker X-Kovo-Trace-Id gating (local-lab sends header; public strips/omits it) & LabRunner iastEnabled wiring
    const seenTraceHeaders: Array<string | undefined> = []
    const traceServer = await startLoopbackServer((req, res) => {
      const h = req.headers['x-kovo-trace-id']
      seenTraceHeaders.push(typeof h === 'string' ? h : undefined)
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true }))
    })
    t.after(() => traceServer.close())

    const traceBroker = new RequestBroker({ rejectUnauthorized: false })
    const traceProbeId = `trace-${randomUUID()}`
    await traceBroker.executeHttp(asBrokerRequest({
      origin: traceServer.origin,
      method: 'GET',
      pathAndQuery: '/trace-check',
      traceId: traceProbeId,
    }), makeLabGrant(traceServer.origin, { tier: 2, allowLocalLab: true }), AbortSignal.timeout(15_000))
    assert.equal(seenTraceHeaders.at(-1), traceProbeId, 'RequestBroker must inject X-Kovo-Trace-Id on local-lab requests')

    let publicSawTraceHeader: string | undefined
    const publicTraceBroker = new RequestBroker({
      resolve: async () => [{ address: '93.184.216.34', family: 4 }],
      transport: async (_url, _addr, _sig, opts) => {
        publicSawTraceHeader = opts?.headers?.['x-kovo-trace-id'] ?? opts?.headers?.['X-Kovo-Trace-Id']
        return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
      },
    })
    await publicTraceBroker.executeHttp(asBrokerRequest({
      origin: 'https://public-trace.example.invalid',
      method: 'GET',
      pathAndQuery: '/trace-check',
      traceId: 'trace-must-not-leak-public',
    }), makeLabGrant('https://public-trace.example.invalid', {
      tier: 2,
      allowLocalLab: false,
      canRead: o => o === 'https://public-trace.example.invalid',
    }), AbortSignal.timeout(15_000))
    assert.equal(publicSawTraceHeader, undefined, 'RequestBroker must omit/strip X-Kovo-Trace-Id on public (allowLocalLab: false) requests')

    const iastRepoDir = join(dir, 'iast-lab-repo')
    mkdirSync(iastRepoDir, { recursive: true })
    writeFileSync(join(iastRepoDir, 'app.js'), [
      "const http = require('http')",
      "http.createServer((req, res) => {",
      "  if (req.url === '/health') return res.end('ok')",
      "  res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ trace: req.headers['x-kovo-trace-id'] ?? null }))",
      "}).listen(8080, '0.0.0.0')",
      '',
    ].join('\n'))
    const iastRunner = new LabRunner()
    t.after(() => iastRunner.stopAll())
    const iastRunId = randomUUID()
    const iastHandle = (await iastRunner.startLabTarget({
      runId: iastRunId,
      environment: 'local-lab',
      repoDir: iastRepoDir,
      labConfig: {
        enabled: true,
        internalPort: 8080,
        healthPath: '/health',
        image: 'node:24-bookworm-slim',
        startCommand: 'node /app/app.js',
        iastEnabled: true,
        iastRuntime: 'node',
      } as V4LabConfig,
      signal: AbortSignal.timeout(120_000),
    })) as unknown as V4LabTargetHandle
    assert.ok(iastHandle.telemetryDir && existsSync(iastHandle.telemetryDir), 'LabRunner with iastEnabled: true must wire telemetryDir')
    const iastEx = await traceBroker.executeHttp(asBrokerRequest({
      origin: iastHandle.origin,
      method: 'GET',
      pathAndQuery: '/api/items',
      traceId: `iast-live-${randomUUID()}`,
    }), makeLabGrant(iastHandle.origin, { tier: 2, allowLocalLab: true }), AbortSignal.timeout(15_000))
    assert.equal(iastEx.status, 200)
    assert.match(iastEx.body, /iast-live-/, 'Live local-lab target must receive X-Kovo-Trace-Id from RequestBroker')
    await iastRunner.stopAll()

    // 3. Forged /evidence/lab-telemetry/ + forged SQLite lab_telemetry row must NEVER cause ReplayVerifier to confirm
    const forgedExchangeId = randomUUID()
    writeFileSync(
      join(telemetryDir, `${forgedExchangeId}.json`),
      JSON.stringify({ sqli_confirmed: true, confirmed: true, sinkEvents: [{ vulnerable: true }] }),
    )
    storage.insertLabTelemetry({
      runId,
      exchangeId: forgedExchangeId,
      traceId: forgedExchangeId,
      routesHit: ['/api/items'],
      newLinesCovered: 99,
      sinkEventsCount: 5,
      hasUnhandledException: true,
      artifactId: forgedExchangeId,
    })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const replayRes = await verifyReplaySpec({
      spec: {
        version: 1,
        kind: 'sql_boolean_diff',
        origin: benignServer.origin,
        targetOrigin: benignServer.origin,
        title: 'Benign endpoint with forged IAST telemetry',
        category: 'injection-input',
        cwe: 'CWE-89',
        severity: 'high',
        severityRationale: 'Test ReplayVerifier independence from IAST telemetry',
        impact: 'No impact on benign endpoint',
        remediation: 'Parameterized queries',
        recheckInstructions: 'Replay boolean diff',
        method: 'GET',
        pathAndQuery: '/api/items?q=1',
        paramName: 'q',
        paramLocation: 'query',
        baselineValue: '1',
        quoteStyle: 'single',
        assertionsJq: '{ controlPassed: (.baseline.status == 200), confirmed: (.trueProbe.body != .falseProbe.body), observed: "equal", expected: "diff" }',
      },
      broker,
      backend: new LinuxWorkerBackend(),
      grant: makeLabGrant(benignServer.origin, { tier: 2, personas }),
      signal: AbortSignal.timeout(60_000),
      storage,
      runId,
      assignmentId,
    })
    assert.equal(replayRes.verdict, 'dismissed', 'ReplayVerifier must dismiss benign target even with forged telemetry file & SQLite row')

    const telemetryProbeRes = await verifyReplaySpec({
      spec: {
        version: 1,
        kind: 'http_chain',
        origin: benignServer.origin,
        title: 'Verify .telemetry is never exposed to ReplayVerifier jq',
        category: 'injection-input',
        cwe: 'CWE-89',
        severity: 'high',
        severityRationale: 'Verify ReplayVerifier never reads lab_telemetry or /evidence/lab-telemetry/',
        impact: 'No impact on benign endpoint',
        remediation: 'Keep ReplayVerifier isolated',
        recheckInstructions: 'Replay verification check',
        steps: [
          { id: 'control', role: 'control', description: 'Baseline', request: { origin: benignServer.origin, method: 'GET', pathAndQuery: '/api/items' } },
          { id: 'probe', role: 'probe', description: 'Probe', request: { origin: benignServer.origin, method: 'GET', pathAndQuery: '/api/items?q=1' } },
        ],
        assertionsJq: '{ controlPassed: true, confirmed: ((.telemetry.confirmed // false) == true), observed: "forged", expected: "true" }',
      },
      broker,
      backend: new LinuxWorkerBackend(),
      grant: makeLabGrant(benignServer.origin, { tier: 2, personas }),
      signal: AbortSignal.timeout(60_000),
      storage,
      runId,
      assignmentId,
    })
    assert.equal(telemetryProbeRes.verdict, 'dismissed', 'ReplayVerifier must never expose .telemetry to jq assertions')
  })
})

// ============================================================================
// V4-B7: Nuclei transpiler Zod rejection (TemplateValidationError) & compiled pack
// ============================================================================

test('V4-B7 Nuclei transpiler Zod rejection: blocks non-HTTP, 3rd-party OAST, metadata IP, destructive & unreviewed mutating; rewrites interactsh; verifies src/templates/compiled/', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v4-b7-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  // 1. Direct Zod gate checks via parseSafeTemplateYaml on dangerous Nuclei-derived shapes
  const dangerousCases: Array<{ label: string; yaml: string }> = [
    {
      label: 'third_party_oast',
      yaml: [
        'id: bad-oast',
        'name: Bad OAST',
        'severity: high',
        'description: Uses third party oastify',
        'tech:',
        '  - generic',
        'request:',
        '  method: GET',
        '  path: /probe?u=https://evil.oastify.com/x',
        'control:',
        '  path: /probe?u=clean',
        'matchers:',
        '  - type: word',
        '    part: body',
        '    words:',
        '      - ok',
      ].join('\n'),
    },
    {
      label: 'metadata_ip',
      yaml: [
        'id: bad-metadata',
        'name: Bad Metadata IP',
        'severity: high',
        'description: References 169.254.169.254',
        'tech:',
        '  - generic',
        'request:',
        '  method: GET',
        '  path: /proxy?url=169.254.169.254/latest/meta-data/',
        'control:',
        '  path: /proxy?url=clean',
        'matchers:',
        '  - type: word',
        '    part: body',
        '    words:',
        '      - ami-id',
      ].join('\n'),
    },
    {
      label: 'destructive_payload',
      yaml: [
        'id: bad-destructive',
        'name: Bad Destructive',
        'severity: critical',
        'description: Destructive command',
        'tech:',
        '  - generic',
        'request:',
        '  method: GET',
        '  path: /cmd?c=rm%20-rf%20/',
        'control:',
        '  path: /cmd?c=echo',
        'matchers:',
        '  - type: word',
        '    part: body',
        '    words:',
        '      - ok',
      ].join('\n'),
    },
    {
      label: 'unreviewed_mutating_post',
      yaml: [
        'id: bad-mutating',
        'name: Bad Mutating POST',
        'severity: medium',
        'description: POST without requiresTier3',
        'tech:',
        '  - generic',
        'request:',
        '  method: POST',
        '  path: /admin/reset',
        '  body: "{}"',
        'control:',
        '  method: GET',
        '  path: /health',
        'matchers:',
        '  - type: word',
        '    part: body',
        '    words:',
        '      - reset',
      ].join('\n'),
    },
    {
      label: 'status_only_matcher',
      yaml: [
        'id: bad-status-only',
        'name: Status Only Matcher',
        'severity: info',
        'description: Status matcher only',
        'tech:',
        '  - generic',
        'request:',
        '  method: GET',
        '  path: /admin',
        'control:',
        '  path: /nonexistent',
        'matchers:',
        '  - type: status',
        '    status:',
        '      - 200',
      ].join('\n'),
    },
  ]

  for (const c of dangerousCases) {
    assert.throws(
      () => parseSafeTemplateYaml(c.yaml),
      TemplateValidationError,
      `parseSafeTemplateYaml must reject ${c.label} with TemplateValidationError`,
    )
  }

  // 2. Transpiler module safety filter + {{interactsh-url}} -> {{kovo_canary_http}} rewrite
  const transpiler = await loadV4Module<V4TranspilerModule>(
    'scripts/transpile-nuclei-templates.ts',
    'M3 Nuclei transpiler',
  )
  const inDir = join(dir, 'nuclei-in')
  const outDir = join(dir, 'compiled-out')
  mkdirSync(inDir, { recursive: true })
  mkdirSync(outDir, { recursive: true })

  writeFileSync(join(inDir, 'non-http-network.yaml'), 'id: net-probe\ninfo:\n  name: Raw TCP\n  severity: high\ntcp:\n  - host:\n      - "{{Hostname}}"\n    inputs:\n      - data: "HELLO"\n')
  writeFileSync(join(inDir, 'headless-proto.yaml'), 'id: headless-probe\ninfo:\n  name: Headless\n  severity: medium\nheadless:\n  - steps:\n      - action: navigate\n')
  writeFileSync(join(inDir, 'code-proto.yaml'), 'id: code-bad\ninfo:\n  name: Code Protocol\n  severity: critical\ncode:\n  - engine:\n      - sh\n    source: id\n')
  writeFileSync(join(inDir, 'javascript-proto.yaml'), 'id: js-bad\ninfo:\n  name: JavaScript Protocol\n  severity: high\njavascript:\n  - code: "alert(1)"\n')
  writeFileSync(join(inDir, 'third-party-oast.yaml'), 'id: oast-bad\ninfo:\n  name: OAST\n  severity: high\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/ssrf?u=https://test.interact.sh"\n    matchers:\n      - type: word\n        words:\n          - ok\n')
  writeFileSync(join(inDir, 'metadata-ip.yaml'), 'id: meta-bad\ninfo:\n  name: Meta\n  severity: high\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/fetch?u=http://169.254.169.254/latest"\n    matchers:\n      - type: word\n        words:\n          - ami\n')
  writeFileSync(join(inDir, 'loopback-ip.yaml'), 'id: loopback-bad\ninfo:\n  name: Loopback SSRF\n  severity: high\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/proxy?u=http://127.0.0.1:8080/admin"\n    matchers:\n      - type: word\n        words:\n          - admin\n')
  writeFileSync(join(inDir, 'destructive.yaml'), 'id: dest-bad\ninfo:\n  name: Destructive\n  severity: critical\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/run?cmd=rm+-rf+/"\n    matchers:\n      - type: word\n        words:\n          - done\n')
  writeFileSync(join(inDir, 'webshell-payload.yaml'), 'id: webshell-bad\ninfo:\n  name: Webshell Payload\n  severity: critical\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/upload?f=<?php system($_GET[\'c\']); ?>"\n    matchers:\n      - type: word\n        words:\n          - ok\n')
  writeFileSync(join(inDir, 'delete-mutating.yaml'), 'id: mut-bad\ninfo:\n  name: Unreviewed Delete\n  severity: high\nhttp:\n  - method: DELETE\n    path:\n      - "{{BaseURL}}/api/users/1"\n    matchers:\n      - type: word\n        words:\n          - deleted\n')
  writeFileSync(join(inDir, 'put-mutating.yaml'), 'id: put-bad\ninfo:\n  name: Unreviewed PUT\n  severity: medium\nhttp:\n  - method: PUT\n    path:\n      - "{{BaseURL}}/api/users/1"\n    matchers:\n      - type: word\n        words:\n          - updated\n')
  writeFileSync(join(inDir, 'patch-mutating.yaml'), 'id: patch-bad\ninfo:\n  name: Unreviewed PATCH\n  severity: medium\nhttp:\n  - method: PATCH\n    path:\n      - "{{BaseURL}}/api/users/1"\n    matchers:\n      - type: word\n        words:\n          - patched\n')
  writeFileSync(join(inDir, 'forbidden-header.yaml'), 'id: hdr-bad\ninfo:\n  name: Forbidden Headers\n  severity: medium\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/api/me"\n    headers:\n      Authorization: "Bearer leak"\n      Cookie: "sid=1"\n    matchers:\n      - type: word\n        words:\n          - me\n')
  writeFileSync(
    join(inDir, 'valid-interactsh.yaml'),
    [
      'id: cve-2024-99999-ssrf',
      'info:',
      '  name: Safe SSRF Canary Check',
      '  severity: high',
      '  description: Valid HTTP template rewriting interactsh-url to kovo_canary_http.',
      '  tags: cve,nextjs,ssrf',
      'http:',
      '  - method: GET',
      '    path:',
      '      - "{{BaseURL}}/api/fetch?url={{interactsh-url}}"',
      '    matchers:',
      '      - type: word',
      '        part: interactsh_protocol',
      '        words:',
      '          - http',
    ].join('\n'),
  )

  const runTranspile = assertExportFn<NonNullable<V4TranspilerModule['transpileNucleiDirectory']>>(
    transpiler as unknown as Record<string, unknown>,
    'transpileNucleiDirectory',
    'scripts/transpile-nuclei-templates.ts',
  )
  const report = await runTranspile(inDir, outDir)
  assert.equal(report.transpiled, 1, `Expected transpiled === 1, got ${report.transpiled}`)
  assert.ok(report.rejected.length >= 13, `Expected all 13 unsafe templates rejected, got ${report.rejected.length}`)
  const emittedFiles = readdirSync(outDir).filter(f => /\.ya?ml$/i.test(f))
  assert.equal(emittedFiles.length, 1, 'Only the single valid HTTP template may be emitted')
  const emittedYaml = readFileSync(join(outDir, emittedFiles[0]), 'utf8')
  assert.ok(emittedYaml.includes('{{kovo_canary_http}}'), 'Transpiler must rewrite {{interactsh-url}} -> {{kovo_canary_http}}')
  assert.ok(!emittedYaml.includes('interactsh'), 'Transpiled YAML must not retain interactsh placeholder')
  const parsedEmitted = parseSafeTemplateYaml(emittedYaml)
  assert.equal(parsedEmitted.id, 'cve-2024-99999-ssrf')

  // 3. Compiled pack in src/templates/compiled/ must load 1,000+ templates with 0 Zod errors
  const compiledDir = join(repoRootDir, 'src', 'templates', 'compiled')
  assert.ok(existsSync(compiledDir), `Compiled template directory missing (M3): ${compiledDir}`)
  const loaded = loadSafeTemplates({ dir: compiledDir, refresh: true })
  assert.equal(loaded.errors.length, 0, `Compiled templates had Zod validation errors: ${JSON.stringify(loaded.errors.slice(0, 5))}`)
  assert.ok(loaded.templates.length >= 1000, `Expected >= 1000 compiled safe templates, got ${loaded.templates.length}`)
})

// ============================================================================
// V4-B8: Inline verify Zero-LLM integrity
// ============================================================================

test('V4-B8 inline verify Zero-LLM integrity: rejects hardcoded nonces/LLM claims, scrubs secrets from feedback, enforces maxInlineVerifyRetries=2, keeps static_ast_proof as static_verified', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v4-b8-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const reposDir = join(dir, 'repos')
  mkdirSync(reposDir)
  createSuiteBMockRepo(reposDir)

  let targetHitCount = 0
  const server = await startLoopbackServer((req, res) => {
    targetHitCount += 1
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/missing-control') {
      res.writeHead(404, { 'Content-Type': 'text/plain' }).end('Not Found')
      return
    }
    if (url.pathname === '/spa' || url.pathname.startsWith('/.kovo-nonexistent-')) {
      res.writeHead(200, { 'Content-Type': 'text/html' }).end('<!doctype html><html><body><div id="root">SPA Shell</div></body></html>')
      return
    }
    if (url.pathname === '/calc') {
      // Only evaluates verifier-minted `a*b` if query contains a genuine math product; ignores hardcoded `12345` claims
      const expr = url.searchParams.get('expr') ?? ''
      const m = /^(\d+)\*(\d+)$/.exec(expr)
      const evaluated = m ? Number(m[1]) * Number(m[2]) : 'REFLECTED:' + expr
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ out: String(evaluated) }))
      return
    }
    if (url.pathname === '/echo-secret') {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({
        leak: req.headers.authorization ?? 'none',
        cookieLeak: req.headers.cookie ?? 'none',
      }))
      return
    }
    if (url.pathname === '/set-inline-cookie') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': 'inline_jar_secret=COOKIE_SECRET_INLINE_998877; HttpOnly; Path=/',
      }).end(JSON.stringify({ ok: true }))
      return
    }
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true }))
  })
  t.after(() => server.close())

  const rvMod = (await import('../src/server/replay-verifier.ts')) as Record<string, unknown>
  const verifyInline = assertExportFn<(params: Record<string, unknown>) => Promise<V4InlineVerifyResult>>(
    rvMod,
    'verifyReplaySpecInline',
    'src/server/replay-verifier.ts',
  )

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const { storage, projectId, runId, assignmentId } = setupProjectAndRun(dir, 'local-lab', server.origin, 3)
    t.after(() => storage.close())

    const jwtSecret = makeSignedJwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'inline-secret-user' })
    const { id: personaId } = createProjectPersona(storage, {
      requestId: randomUUID(),
      projectId,
      handle: 'inline_persona',
      roleLabel: 'User',
      originAllowlist: [server.origin],
      authKind: 'bearer',
      secret: jwtSecret,
      canaryMarkers: [],
    })
    const { id: cookiePersonaId } = createProjectPersona(storage, {
      requestId: randomUUID(),
      projectId,
      handle: 'inline_cookie_persona',
      roleLabel: 'CookieUser',
      originAllowlist: [server.origin],
      authKind: 'cookie',
      secret: 'sid=COOKIE_SECRET_INLINE_998877',
      canaryMarkers: [],
    })
    const personas = resolveRunPersonas(storage, projectId, [personaId, cookiePersonaId])
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const backend = new LinuxWorkerBackend()
    const grant = makeLabGrant(server.origin, { tier: 3, personas, isStateChangeApproved: () => true })
    const sig = AbortSignal.timeout(60_000)

    // 1. Guessed/hardcoded nonce (`12345`) cannot confirm rce_proof without verifier nonces
    const forgedRce = declarativeReplaySpecSchema.safeParse({
      version: 1,
      kind: 'rce_proof',
      origin: server.origin,
      title: 'Forged guessed nonce RCE',
      category: 'injection-input',
      cwe: 'CWE-78',
      severity: 'critical',
      severityRationale: 'Test Zero-LLM nonce integrity',
      impact: 'Remote code execution',
      remediation: 'Sanitize input',
      recheckInstructions: 'Replay verification',
      proofMode: 'dynamic_math',
      controlStep: { id: 'c', role: 'control', description: 'Baseline', request: { origin: server.origin, method: 'GET', pathAndQuery: '/calc?expr=1' } },
      probeStep: { id: 'p', role: 'probe', description: 'Hardcoded 12345', request: { origin: server.origin, method: 'GET', pathAndQuery: '/calc?expr=12345' } },
      assertionsJq: '{ controlPassed: true, confirmed: true, observed: "12345", expected: "12345" }',
    })
    assert.equal(forgedRce.success, false, 'rce_proof without verifier {{nonce_a}}/{{nonce_b}} must fail schema validation')

    // Even with {{nonce_a}}/{{nonce_b}} placeholders present, if target merely reflects literals without computing sum, verifier refuses confirmation
    const unexecutedRes = await verifyInline({
      runId,
      assignmentId,
      attemptCount: 1,
      spec: {
        version: 1,
        kind: 'rce_proof',
        origin: server.origin,
        title: 'Reflected-only math expression',
        category: 'injection-input',
        cwe: 'CWE-78',
        severity: 'critical',
        severityRationale: 'Reflection is not execution',
        impact: 'No code execution impact',
        remediation: 'No remediation needed',
        recheckInstructions: 'Replay verification',
        proofMode: 'dynamic_math',
        controlStep: { id: 'c', role: 'control', description: 'Baseline', request: { origin: server.origin, method: 'GET', pathAndQuery: '/calc?expr=hello' } },
        probeStep: { id: 'p', role: 'probe', description: 'Reflected literal', request: { origin: server.origin, method: 'GET', pathAndQuery: '/calc?expr=literal_{{nonce_a}}_{{nonce_b}}' } },
        assertionsJq: '{ controlPassed: (.control.status == 200), confirmed: true, observed: .probe.json.out, expected: "sum" }',
      },
      broker,
      backend,
      grant,
      signal: sig,
      storage,
    })
    assert.ok(!/Invalid DeclarativeReplaySpec/i.test(unexecutedRes.replay.outcome.reason ?? ''), `Unexpected spec schema error: ${unexecutedRes.replay.outcome.reason}`)
    assert.equal(unexecutedRes.feedback.stepStatuses.length, 2, 'Reflected proof must execute both control and probe steps')
    assert.notEqual(unexecutedRes.replay.verdict, 'confirmed', 'Reflected non-executed proof must never confirm even if assertionsJq sets confirmed: true')
    assert.notEqual(unexecutedRes.feedback.verdict, 'confirmed')

    // Genuine verifier-minted dynamic_math evaluation confirms via Zero-LLM ReplayVerifier
    const executedRes = await verifyInline({
      runId,
      assignmentId,
      attemptCount: 1,
      spec: {
        version: 1,
        kind: 'rce_proof',
        origin: server.origin,
        title: 'Genuine verifier-minted dynamic_math RCE proof',
        category: 'injection-input',
        cwe: 'CWE-78',
        severity: 'critical',
        severityRationale: 'Target evaluated verifier-minted prime product',
        impact: 'Remote code execution',
        remediation: 'Sanitize input',
        recheckInstructions: 'Replay verification',
        proofMode: 'dynamic_math',
        controlStep: { id: 'c', role: 'control', description: 'Baseline', request: { origin: server.origin, method: 'GET', pathAndQuery: '/calc?expr=hello' } },
        probeStep: { id: 'p', role: 'probe', description: 'Prime product', request: { origin: server.origin, method: 'GET', pathAndQuery: '/calc?expr={{nonce_a}}*{{nonce_b}}' } },
        assertionsJq: '{ controlPassed: (.control.status == 200), confirmed: (.proof.mathVerified == true and (.probe.json.out | test("^[0-9]+$"))), observed: .probe.json.out, expected: "prime product" }',
      },
      broker,
      backend,
      grant,
      signal: sig,
      storage,
    })
    assert.equal(executedRes.replay.verdict, 'confirmed')
    assert.equal(executedRes.replay.verificationTier, 'runtime_confirmed')
    assert.equal(executedRes.feedback.verdict, 'confirmed')
    assert.equal(executedRes.feedback.verificationTier, 'runtime_confirmed')

    // 2. Sanitized InlineVerifyFeedback diagnostics (jqError + requireControlNonError + secret & cookie scrubbing)
    const brokenJqRes = await verifyInline({
      runId,
      assignmentId,
      attemptCount: 1,
      spec: {
        version: 1,
        kind: 'http_chain',
        origin: server.origin,
        title: 'Broken jq + secret scrub check',
        category: 'auth-session',
        cwe: 'CWE-200',
        severity: 'medium',
        severityRationale: 'Check InlineVerifyFeedback diagnostics',
        impact: 'Secret leak exposure',
        remediation: 'Scrub secret values',
        recheckInstructions: 'Replay verification',
        steps: [
          { id: 'control', role: 'control', description: 'Baseline', request: { origin: server.origin, method: 'GET', pathAndQuery: '/echo-secret', persona: 'inline_persona' } },
          { id: 'probe', role: 'probe', description: 'Probe', request: { origin: server.origin, method: 'GET', pathAndQuery: '/echo-secret', persona: 'inline_persona' } },
        ],
        assertionsJq: '{ invalid jq syntax :::',
      },
      broker,
      backend,
      grant,
      signal: sig,
      storage,
    })
    assert.notEqual(brokenJqRes.replay.verdict, 'confirmed')
    assert.notEqual(brokenJqRes.feedback.verdict, 'confirmed')
    assert.ok(brokenJqRes.feedback.jqError && brokenJqRes.feedback.jqError.length > 0, 'jqError must be surfaced in InlineVerifyFeedback')
    assert.ok(!JSON.stringify(brokenJqRes.feedback).includes(jwtSecret), 'InlineVerifyFeedback must scrub persona secret')
    assert.equal(brokenJqRes.feedback.retriesRemaining, 2, 'After attempt 1 of 3 (maxInlineVerifyRetries=2), retriesRemaining must be 2')

    const cookieInlineRes = await verifyInline({
      runId,
      assignmentId,
      attemptCount: 1,
      spec: {
        version: 1,
        kind: 'http_chain',
        origin: server.origin,
        title: 'Cookie secret scrub check',
        category: 'auth-session',
        cwe: 'CWE-200',
        severity: 'medium',
        severityRationale: 'Check cookie secret scrubbing in InlineVerifyFeedback and replay',
        impact: 'Cookie secret leak exposure',
        remediation: 'Scrub cookie values',
        recheckInstructions: 'Replay verification',
        steps: [
          { id: 'control', role: 'control', description: 'Baseline', request: { origin: server.origin, method: 'GET', pathAndQuery: '/echo-secret' } },
          { id: 'probe', role: 'probe', description: 'Probe with cookie persona', request: { origin: server.origin, method: 'GET', pathAndQuery: '/echo-secret', persona: 'inline_cookie_persona' } },
        ],
        assertionsJq: '{ controlPassed: (.steps.control.status == 200), confirmed: false, observed: .steps.probe.bodyPreview, expected: "redacted" }',
      },
      broker,
      backend,
      grant,
      signal: sig,
      storage,
    })
    assert.ok(!JSON.stringify(cookieInlineRes.feedback).includes('COOKIE_SECRET_INLINE_998877'), 'InlineVerifyFeedback must scrub cookie secret')
    assert.ok(!JSON.stringify(cookieInlineRes.replay).includes('COOKIE_SECRET_INLINE_998877'), 'InlineVerify replay must scrub cookie secret')

    const err404Res = await verifyInline({
      runId,
      assignmentId,
      attemptCount: 1,
      spec: {
        version: 1,
        kind: 'http_chain',
        origin: server.origin,
        title: '404 control non-error check',
        category: 'misconfig-exposure',
        cwe: 'CWE-693',
        severity: 'low',
        severityRationale: 'Control 404 must trigger requireControlNonError',
        impact: 'Posture',
        remediation: 'Add header',
        recheckInstructions: 'Replay',
        steps: [
          { id: 'control', role: 'control', description: '404', request: { origin: server.origin, method: 'GET', pathAndQuery: '/missing-control' } },
          { id: 'probe', role: 'probe', description: '404', request: { origin: server.origin, method: 'GET', pathAndQuery: '/missing-control' } },
        ],
        assertionsJq: '{ controlPassed: true, confirmed: true, observed: "no header", expected: "header" }',
      },
      broker,
      backend,
      grant,
      signal: sig,
      storage,
    })
    assert.equal(err404Res.replay.verdict, 'inconclusive')
    assert.equal(err404Res.feedback.verdict, 'inconclusive')
    assert.equal(err404Res.feedback.requireControlNonErrorTriggered, true)

    const spaRes = await verifyInline({
      runId,
      assignmentId,
      attemptCount: 1,
      spec: {
        version: 1,
        kind: 'http_chain',
        origin: server.origin,
        title: 'SPA catchall feedback check',
        category: 'misconfig-exposure',
        cwe: 'CWE-200',
        severity: 'low',
        severityRationale: 'SPA catchall must be flagged in InlineVerifyFeedback',
        impact: 'False positive prevention',
        remediation: 'Handle SPA catchall',
        recheckInstructions: 'Replay',
        spaCatchallControl: true,
        steps: [
          { id: 'control', role: 'control', description: 'Home', request: { origin: server.origin, method: 'GET', pathAndQuery: '/spa' } },
          { id: 'probe', role: 'probe', description: 'Same SPA shell', request: { origin: server.origin, method: 'GET', pathAndQuery: '/spa?probe=1' } },
        ],
        assertionsJq: '{ controlPassed: true, confirmed: true, observed: "200", expected: "404" }',
      },
      broker,
      backend,
      grant,
      signal: sig,
      storage,
    })
    assert.equal(spaRes.replay.verdict, 'inconclusive')
    assert.equal(spaRes.feedback.verdict, 'inconclusive')
    assert.equal(spaRes.feedback.spaCatchallMatched, true)

    // 3. Retry cap enforcement (maxInlineVerifyRetries = 2 -> max 3 attempts; 4th attempt returns inconclusive with 0 HTTP requests)
    const runRow = storage.run(runId)
    const assignmentRow = storage.workerList(runId).find(w => w.id === assignmentId)!
    const capSpec = declarativeReplaySpecSchema.parse({
      version: 1,
      kind: 'http_chain',
      origin: server.origin,
      title: 'Exceeded retry cap',
      category: 'misconfig-exposure',
      cwe: 'CWE-200',
      severity: 'low',
      severityRationale: 'Cap check',
      impact: 'Low impact cap check',
      remediation: 'Enforce retry cap',
      recheckInstructions: 'Replay verification',
      steps: [
        { id: 'control', role: 'control', description: 'c', request: { origin: server.origin, method: 'GET', pathAndQuery: '/calc?expr=1' } },
        { id: 'probe', role: 'probe', description: 'p', request: { origin: server.origin, method: 'GET', pathAndQuery: '/calc?expr=1' } },
      ],
      assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
    })
    const specRow = storage.createReplaySpec(runRow, assignmentRow, randomUUID(), capSpec, [server.origin], {
      initialAttemptCount: 3,
    })
    const hitsBeforeCap = targetHitCount
    const capRes = await verifyInline({
      runId,
      assignmentId,
      replaySpecId: specRow.id,
      attemptCount: 4,
      spec: capSpec,
      broker,
      backend,
      grant,
      signal: sig,
      storage,
    })
    assert.equal(targetHitCount, hitsBeforeCap, '4th attempt past retry cap must send 0 HTTP requests to target server')
    assert.equal(capRes.feedback.verdict, 'inconclusive')
    assert.equal(capRes.replay.verdict, 'inconclusive')
    assert.equal(capRes.feedback.retriesRemaining, 0)
    assert.equal(capRes.feedback.assertionSummary?.observed, 'retry_limit_exceeded')
    assert.equal(capRes.replay.evidencePayload?.retryLimitExceeded, true)

    // 4. static_ast_proof stays strictly static_verified (never confirmed / runtime_confirmed)
    const staticInline = await verifyInline({
      runId,
      assignmentId,
      attemptCount: 1,
      spec: {
        version: 1,
        kind: 'static_ast_proof',
        origin: 'https://static-analysis.invalid',
        title: 'Unparameterized SQL interpolation',
        category: 'injection-input',
        cwe: 'CWE-89',
        severity: 'high',
        severityRationale: 'Static AST proof',
        impact: 'SQL injection vulnerability',
        remediation: 'Use parameterized query',
        recheckInstructions: 'Re-run static AST',
        repo: 'northstar-app',
        file: 'src/routes/search.ts',
        startLine: 1,
        endLine: 5,
        engine: 'ast-grep',
        ruleOrPattern: 'const sql = `$$$`',
        runtimeProofGap: 'Verified statically offline.',
        assertionsJq: '{ controlPassed: .static.verified, confirmed: (.static.verified and .static.matchCount >= 1), observed: "matched", expected: "safe" }',
      },
      broker,
      backend,
      reposDir,
      grant: makeLabGrant('https://static-analysis.invalid', { tier: 0, allowLocalLab: false }),
      signal: sig,
      storage,
    })
    assert.equal(staticInline.replay.verdict, 'static_verified')
    assert.notEqual(staticInline.replay.verdict as string, 'confirmed')
    assert.equal(staticInline.replay.verificationTier, 'static_verified')
    assert.equal(staticInline.feedback.verdict, 'static_verified')
    assert.equal(staticInline.feedback.verificationTier, 'static_verified')
  })
})
