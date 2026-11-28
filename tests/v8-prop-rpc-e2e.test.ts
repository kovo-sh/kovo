/**
 * Full-Stack Loopback E2E & Adversarial Integration Suite for v8 Multi-Hop Verification.
 *
 * Defensive QA: executes real TypeScript `kovo_verify.ts` scripts through the FULL stack:
 *   `verifyScript()` (dual fresh clean replay)
 *     -> `createLocalAttemptFactory()` (spawns real `node` candidate per attempt)
 *     -> `VerifyRpcServer` (Unix-socket RPC, DerivedCapabilityVault, host-signed transcript)
 *     -> `RequestBroker` + `redact.ts` (credential injection, secret scrubbing, race burst)
 *     -> multi-port in-process loopback HTTP fixture servers (`apiOrigin` + `artifactOrigin`)
 *
 * Covers:
 *   - All 4 causal edge kinds: `value_binding`, `derived_crypto_binding`,
 *     `state_transition_binding`, `async_pivot_binding`.
 *   - Major terminal oracle families: `dual_tenant_abac`, `economic_conservation`
 *     (including auto-hydration), `cryptographic_scope_replay`, `cross_surface_pivot`
 *     (async cross-tenant exfiltration).
 *   - Queue #27–#34 multi-hop regression surface: JSON redaction integrity, pre-redacted
 *     `capability.seal`, `Bearer Bearer` dedup & cookie shadowing avoidance, path-interpolated
 *     `valueDigest`, late-seal race-burst backfill, `hmac_sign` & `jwt_sign` derivation,
 *     fresh per-run IDs + Run 1 vs Run 2 race-winner order jitter.
 *   - Adversarial fail-closed tests: intermediate job/export/signed-URL stubs
 *     (`terminal_impact_unproven`), missing/dirty/passing ablation controls, unbound
 *     `value_binding`, forged/out-of-order `derived_crypto_binding`, and genuine Run 1 vs
 *     Run 2 route/claim disagreement (`transcript_mismatch`).
 */
import assert from 'node:assert/strict'
import { createHmac, randomBytes, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { createLocalAttemptFactory } from '../src/server/verify-rpc.ts'
import { verifyScript } from '../src/server/verify-runner.ts'
import type { VerifyVerdict } from '../src/server/verify-runner.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SDK_DIR = join(REPO_ROOT, 'worker', 'kovo_verify')

// Realistic secret literals (all generic, zero benchmark identifiers)
const DUAL_MEMBER_BEARER = 'dual_mem_base_tok_91a2b3c4d5e6f708'
const MEMBER_B_BEARER = 'mem_b_base_tok_778899aabbccddeeff'
const COOKIE_MEMBER_SID = 'base_cookie_sid_1029384756abcdef'
const MINTED_VAULT_BEARER = 'vault_minted_tok_33445566778899aa'
const MINTED_VAULT_COOKIE = 'vault_sess_ck_5566778899aabbccdd'
const RAW_HMAC_SECRET = 'hmac_signing_key_live_0011223344556677'
const RAW_JWT_SECRET = 'jwt_signing_key_live_8899aabbccddeeff'
const RAW_DOWNLOAD_TOKEN = 'artifact_dl_tok_fedcba9876543210'
const UNUSED_ORDER_SECRET = 'unused_order_tok_1234567890abcdef'

const ALL_RAW_SECRETS = [
  DUAL_MEMBER_BEARER,
  MEMBER_B_BEARER,
  COOKIE_MEMBER_SID,
  MINTED_VAULT_BEARER,
  MINTED_VAULT_COOKIE,
  RAW_HMAC_SECRET,
  RAW_JWT_SECRET,
  RAW_DOWNLOAD_TOKEN,
  UNUSED_ORDER_SECRET,
] as const

interface WireCapture {
  origin: 'api' | 'artifact'
  attempt: number
  method: string
  pathAndQuery: string
  authorization: string | undefined
  cookie: string | undefined
  xSig: string | undefined
  body: string
}

interface AsyncJobState {
  jobId: string
  correlationId: string
  targetTenant: string
  pollCount: number
}

interface AttemptFixtureState {
  attempt: 1 | 2
  cachePrimed: boolean
  ledgerBalance: number
  orders: Map<string, { orderId: string; amount: number; settleCalls: number }>
  jobs: Map<string, AsyncJobState>
  divergentTokens: Map<string, string>
}

let activeState: AttemptFixtureState = makeAttemptState(1)
const wireCaptures: WireCapture[] = []

function makeAttemptState(attempt: 1 | 2): AttemptFixtureState {
  return {
    attempt,
    cachePrimed: false,
    ledgerBalance: 100,
    orders: new Map(),
    jobs: new Map(),
    divergentTokens: new Map(),
  }
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolveBody, rejectBody) => {
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(Buffer.from(c)))
    req.on('end', () => resolveBody(Buffer.concat(chunks).toString('utf8')))
    req.on('error', rejectBody)
  })
}

function jsonRes(res: ServerResponse, status: number, value: unknown, extraHeaders?: Record<string, string>): void {
  const body = JSON.stringify(value)
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body),
    ...(extraHeaders ?? {}),
  })
  res.end(body)
}

function verifyHs256Jwt(token: string, secret: string): Record<string, unknown> | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  const [h, p, s] = parts
  const expected = createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url')
  if (expected !== s) return null
  try {
    return JSON.parse(Buffer.from(p!, 'base64url').toString('utf8')) as Record<string, unknown>
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// Multi-Port Loopback Fixture Servers: `apiServer` (Port 1) & `artifactServer` (Port 2)
// ---------------------------------------------------------------------------

let apiOrigin = ''
let artifactOrigin = ''

const apiServer = createServer(async (req, res) => {
  const rawBody = await readBody(req)
  const url = new URL(req.url ?? '/', 'http://127.0.0.1')
  const auth = typeof req.headers.authorization === 'string' ? req.headers.authorization : undefined
  const cookie = typeof req.headers.cookie === 'string' ? req.headers.cookie : undefined
  const xSig = typeof req.headers['x-sig'] === 'string' ? req.headers['x-sig'] : undefined
  wireCaptures.push({
    origin: 'api',
    attempt: activeState.attempt,
    method: req.method ?? 'GET',
    pathAndQuery: url.pathname + url.search,
    authorization: auth,
    cookie,
    xSig,
    body: rawBody,
  })

  // --- Workflow 1: Dual-tenant cache bleed + derived bearer/cookie ---
  if (url.pathname === '/api/v1/cache/prime' && req.method === 'POST') {
    if (auth !== `Bearer ${DUAL_MEMBER_BEARER}`) return jsonRes(res, 401, { error: 'auth_required' })
    activeState.cachePrimed = true
    return jsonRes(res, 200, {
      primed: true,
      tenant: 'org_prime',
      targetScope: 'org_target',
      vault_token: MINTED_VAULT_BEARER,
      prefixed_vault_token: `Bearer ${MINTED_VAULT_BEARER}`,
      nullable_token: null,
      token_count: 4,
    }, { 'set-cookie': `vault_ck=${MINTED_VAULT_COOKIE}; Path=/; HttpOnly` })
  }

  if (url.pathname === '/api/v1/orgs/org_target/records' && req.method === 'GET') {
    if (auth !== `Bearer ${DUAL_MEMBER_BEARER}`) return jsonRes(res, 401, { error: 'auth_required' })
    if (!activeState.cachePrimed) return jsonRes(res, 403, { error: 'forbidden_in_org_target' })
    return jsonRes(res, 200, {
      tenant: 'org_target',
      recordId: `rec_${activeState.attempt}_${randomBytes(3).toString('hex')}`,
      customerEmail: 'billing@target-corp.example',
      balanceCents: 985000,
      vaultTicket: MINTED_VAULT_BEARER,
    })
  }

  // Always-open endpoint used for negative ablation test (ablation returns 200 instead of denied)
  if (url.pathname === '/api/v1/orgs/org_open/records' && req.method === 'GET') {
    return jsonRes(res, 200, { tenant: 'org_open', customerEmail: 'public@open.example', balanceCents: 100 })
  }

  // --- Workflow 2: Economic conservation + concurrent race burst with Run 1/Run 2 winner jitter ---
  if (url.pathname === '/api/v1/accounts/acct_b/balance' && req.method === 'GET') {
    if (auth !== `Bearer ${MEMBER_B_BEARER}`) return jsonRes(res, 401, { error: 'auth_required' })
    return jsonRes(res, 200, {
      accountId: 'acct_b',
      balance: activeState.ledgerBalance,
      currency: 'USD',
    })
  }

  if (url.pathname === '/api/v1/orders' && req.method === 'POST') {
    if (auth !== `Bearer ${MEMBER_B_BEARER}`) return jsonRes(res, 401, { error: 'auth_required' })
    const orderId = `ord_${activeState.attempt}_${randomBytes(3).toString('hex')}`
    activeState.orders.set(orderId, { orderId, amount: 100, settleCalls: 0 })
    return jsonRes(res, 201, {
      id: orderId,
      amount: 100,
      status: 'open',
      unusedToken: UNUSED_ORDER_SECRET,
    })
  }

  const settleMatch = /^\/api\/v1\/orders\/([^/]+)\/settle-race$/.exec(url.pathname)
  if (settleMatch && req.method === 'POST') {
    if (auth !== `Bearer ${MEMBER_B_BEARER}`) return jsonRes(res, 401, { error: 'auth_required' })
    const orderId = decodeURIComponent(settleMatch[1]!)
    const ord = activeState.orders.get(orderId)
    if (!ord) return jsonRes(res, 404, { error: 'order_not_found' })
    const callIdx = ord.settleCalls
    ord.settleCalls += 1
    // Intentional deterministic race-winner order jitter across Run 1 vs Run 2:
    //   Run 1: indices 1 and 3 win (200), last index 5 loses (409).
    //   Run 2: indices 0 and 5 win (200), last index 5 wins (200) while 1..4 lose (409).
    const winners = activeState.attempt === 1 ? new Set([1, 3]) : new Set([0, 5])
    if (winners.has(callIdx)) {
      activeState.ledgerBalance += ord.amount
      return jsonRes(res, 200, {
        settled: true,
        orderId,
        credited: ord.amount,
        newBalance: activeState.ledgerBalance,
      })
    }
    return jsonRes(res, 409, { error: 'already_settled', orderId })
  }

  // --- Workflow 3: Cryptographic scope replay (HMAC signing) ---
  if (url.pathname === '/api/v1/service/signing-config' && req.method === 'GET') {
    if (auth !== `Bearer ${MEMBER_B_BEARER}`) return jsonRes(res, 401, { error: 'auth_required' })
    return jsonRes(res, 200, {
      tenant: 'org_b',
      scope: 'org_b:billing',
      signing_secret: RAW_HMAC_SECRET,
      algorithm: 'sha256',
    })
  }

  if (url.pathname === '/api/v1/webhooks/apply' && req.method === 'POST') {
    const expectedSig = createHmac('sha256', RAW_HMAC_SECRET).update(rawBody).digest('hex')
    if (!xSig || xSig !== expectedSig) {
      return jsonRes(res, 403, { error: 'invalid_signature' })
    }
    return jsonRes(res, 200, {
      ok: true,
      tenant: 'org_target',
      scope: 'org_target:admin',
      appliedCredit: 500,
      receiptCode: `rcpt_${activeState.attempt}_${randomBytes(3).toString('hex')}`,
    })
  }

  // Decoy webhook that accepts any signature (used to prove host verifier rejects forged/out-of-order derived_crypto_binding)
  if (url.pathname === '/api/v1/webhooks/decoy-accept' && req.method === 'POST') {
    return jsonRes(res, 200, {
      ok: true,
      tenant: 'org_target',
      appliedCredit: 500,
      customerEmail: 'decoy@target-corp.example',
    })
  }

  // --- Workflow 4: Async cross-tenant exfil (JWT sign -> async job queued->ready -> artifact origin download) ---
  if (url.pathname === '/api/v1/export/signing-meta' && req.method === 'GET') {
    if (auth !== `Bearer ${MEMBER_B_BEARER}`) return jsonRes(res, 401, { error: 'auth_required' })
    return jsonRes(res, 200, {
      tenant: 'org_b',
      jwt_secret: RAW_JWT_SECRET,
      issuer: 'export-svc',
    })
  }

  if (url.pathname === '/api/v1/exports/jobs' && req.method === 'POST') {
    const bearer = auth?.startsWith('Bearer ') ? auth.slice(7) : ''
    const claims = verifyHs256Jwt(bearer, RAW_JWT_SECRET)
    if (!claims || claims.scope !== 'export:all') {
      return jsonRes(res, 403, { error: 'invalid_export_jwt' })
    }
    const parsed = rawBody ? JSON.parse(rawBody) as { targetTenant?: string; correlationId?: string } : {}
    const jobId = `job_${activeState.attempt}_${randomBytes(3).toString('hex')}`
    const correlationId = parsed.correlationId ?? `corr_${activeState.attempt}_${randomBytes(3).toString('hex')}`
    activeState.jobs.set(jobId, {
      jobId,
      correlationId,
      targetTenant: parsed.targetTenant ?? 'org_target',
      pollCount: 0,
    })
    return jsonRes(res, 202, {
      jobId,
      state: 'queued',
      correlationId,
      statusUrl: `/api/v1/exports/jobs/${jobId}?corr=${encodeURIComponent(correlationId)}`,
    })
  }

  const jobPollMatch = /^\/api\/v1\/exports\/jobs\/([^/]+)$/.exec(url.pathname)
  if (jobPollMatch && req.method === 'GET') {
    if (auth !== `Bearer ${MEMBER_B_BEARER}`) return jsonRes(res, 401, { error: 'auth_required' })
    const jobId = decodeURIComponent(jobPollMatch[1]!)
    const job = activeState.jobs.get(jobId)
    if (!job) return jsonRes(res, 404, { error: 'job_not_found' })
    job.pollCount += 1
    if (job.pollCount < 2) {
      return jsonRes(res, 200, { jobId: job.jobId, state: 'queued', correlationId: job.correlationId })
    }
    return jsonRes(res, 200, {
      jobId: job.jobId,
      state: 'ready',
      correlationId: job.correlationId,
      download_token: RAW_DOWNLOAD_TOKEN,
      artifactPath: `/v1/artifacts/org_target/export-${job.jobId}.json`,
      artifactUrl: `${artifactOrigin}/v1/artifacts/org_target/export-${job.jobId}.json`,
    })
  }

  // --- Negative (a): Intermediate job/export & signed-URL stubs ---
  if (url.pathname === '/api/v1/exports/stub-job' && req.method === 'POST') {
    if (auth !== `Bearer ${MEMBER_B_BEARER}`) return jsonRes(res, 401, { error: 'auth_required' })
    const jobId = `job_${activeState.attempt}_${randomBytes(3).toString('hex')}`
    return jsonRes(res, 202, {
      jobId,
      state: 'queued',
      downloadUrl: `${artifactOrigin}/v1/artifacts/org_target/export-${jobId}.json`,
    })
  }

  if (url.pathname === '/api/v1/exports/signed-url' && req.method === 'POST') {
    if (auth !== `Bearer ${MEMBER_B_BEARER}`) return jsonRes(res, 401, { error: 'auth_required' })
    return jsonRes(res, 200, {
      signedUrl: `${artifactOrigin}/v1/artifacts/org_target/signed-download?sig=deadbeef`,
      expiresIn: 300,
      token: MINTED_VAULT_BEARER,
    })
  }

  // --- Negative (e): Divergent Run 1 vs Run 2 route/claim disagreement ---
  if (url.pathname === '/api/v1/divergent/start' && req.method === 'POST') {
    if (auth !== `Bearer ${MEMBER_B_BEARER}`) return jsonRes(res, 401, { error: 'auth_required' })
    const itemId = `itm_${activeState.attempt}_${randomBytes(3).toString('hex')}`
    const branch = activeState.attempt === 1 ? 'alpha' : 'beta'
    activeState.divergentTokens.set(itemId, branch)
    return jsonRes(res, 200, {
      itemId,
      nextRoute: `/api/v1/divergent/${branch}/${itemId}`,
      accessToken: MINTED_VAULT_BEARER,
    })
  }

  const divMatch = /^\/api\/v1\/divergent\/(alpha|beta)\/([^/]+)$/.exec(url.pathname)
  if (divMatch && req.method === 'GET') {
    if (auth === `Bearer ${MINTED_VAULT_BEARER}`) {
      return jsonRes(res, 200, {
        tenant: 'org_target',
        branch: divMatch[1],
        itemId: divMatch[2],
        customerEmail: 'secret@target-corp.example',
        balanceCents: 50000,
      })
    }
    return jsonRes(res, 403, { error: 'forbidden' })
  }

  return jsonRes(res, 404, { error: 'not_found' })
})

const artifactServer = createServer(async (req, res) => {
  const rawBody = await readBody(req)
  const url = new URL(req.url ?? '/', 'http://127.0.0.1')
  const auth = typeof req.headers.authorization === 'string' ? req.headers.authorization : undefined
  const cookie = typeof req.headers.cookie === 'string' ? req.headers.cookie : undefined
  wireCaptures.push({
    origin: 'artifact',
    attempt: activeState.attempt,
    method: req.method ?? 'GET',
    pathAndQuery: url.pathname + url.search,
    authorization: auth,
    cookie,
    xSig: undefined,
    body: rawBody,
  })

  if (url.pathname === '/v1/vault/org_target/ledger' && req.method === 'GET') {
    if (auth === `Bearer ${MINTED_VAULT_BEARER}`) {
      return jsonRes(res, 200, {
        tenant: 'org_target',
        ledgerId: `ldg_${activeState.attempt}_${randomBytes(3).toString('hex')}`,
        customerEmail: 'treasury@target-corp.example',
        balanceCents: 1450000,
        note: 'derived-token-verified',
      })
    }
    return jsonRes(res, 403, { error: 'vault_forbidden' })
  }

  if (url.pathname === '/v1/vault/cookie-check' && req.method === 'GET') {
    if (cookie && cookie.includes(`vault_ck=${MINTED_VAULT_COOKIE}`) && !cookie.includes(COOKIE_MEMBER_SID)) {
      return jsonRes(res, 200, {
        tenant: 'org_target',
        actor: 'derived_cookie',
        customerEmail: 'cookie-check@target-corp.example',
      })
    }
    return jsonRes(res, 403, { error: 'cookie_forbidden' })
  }

  if (/^\/v1\/artifacts\/org_target\/export-[^/]+\.json$/.test(url.pathname) && req.method === 'GET') {
    if (auth === `Bearer ${RAW_DOWNLOAD_TOKEN}`) {
      return jsonRes(res, 200, {
        tenant: 'org_target',
        exportedAt: '2026-11-25T00:00:00Z',
        records: [
          { accountId: 'acc-901', ownerEmail: 'finance@target-corp.example', balanceCents: 425000 },
          { accountId: 'acc-902', ownerEmail: 'payroll@target-corp.example', balanceCents: 812000 },
        ],
      })
    }
    return jsonRes(res, 403, { error: 'artifact_forbidden' })
  }

  return jsonRes(res, 404, { error: 'artifact_not_found' })
})

apiServer.listen(0, '127.0.0.1')
artifactServer.listen(0, '127.0.0.1')
await Promise.all([once(apiServer, 'listening'), once(artifactServer, 'listening')])
const apiPort = (apiServer.address() as { port: number }).port
const artifactPort = (artifactServer.address() as { port: number }).port
apiOrigin = `http://127.0.0.1:${apiPort}`
artifactOrigin = `http://127.0.0.1:${artifactPort}`

test.after(async () => {
  apiServer.closeAllConnections()
  artifactServer.closeAllConnections()
  await Promise.all([
    new Promise<void>(r => apiServer.close(() => r())),
    new Promise<void>(r => artifactServer.close(() => r())),
  ])
})

function makeGrant(): Grant {
  const dualMember: ResolvedPersona = {
    id: 'persona-dual-member',
    handle: 'dual_member',
    roleLabel: 'member (org_prime)',
    originAllowlist: [apiOrigin, artifactOrigin],
    authKind: 'bearer',
    headerName: null,
    secret: DUAL_MEMBER_BEARER,
    canaryMarkers: [],
  }
  const memberB: ResolvedPersona = {
    id: 'persona-member-b',
    handle: 'member_b',
    roleLabel: 'member (org_b)',
    originAllowlist: [apiOrigin, artifactOrigin],
    authKind: 'bearer',
    headerName: null,
    secret: MEMBER_B_BEARER,
    canaryMarkers: [],
  }
  const cookieMember: ResolvedPersona = {
    id: 'persona-cookie-member',
    handle: 'cookie_member',
    roleLabel: 'member (org_b)',
    originAllowlist: [apiOrigin, artifactOrigin],
    authKind: 'cookie',
    headerName: null,
    secret: `base_sid=${COOKIE_MEMBER_SID}`,
    canaryMarkers: [],
  }
  return {
    origin: apiOrigin,
    tier: 3,
    allowLocalLab: true,
    allowedPorts: [apiPort, artifactPort],
    maxRpsPerOrigin: 500,
    personas: new Map([
      ['dual_member', dualMember],
      ['member_b', memberB],
      ['cookie_member', cookieMember],
    ]),
    canRead: candidate => candidate === apiOrigin || candidate === artifactOrigin,
    isStateChangeApproved: () => true,
    audit: () => {},
  }
}

function assertNoRawSecretsInVerdict(verdict: VerifyVerdict, label: string): void {
  const serialized = JSON.stringify({
    detail: verdict.detail,
    stderrPreview: verdict.stderrPreview,
    disagreements: verdict.disagreements,
    attempts: verdict.attempts.map(a => ({
      failures: a.failures,
      stderr: a.stderr,
      transcriptSummary: a.transcriptSummary,
    })),
  })
  for (const secret of ALL_RAW_SECRETS) {
    assert.equal(
      serialized.includes(secret),
      false,
      `${label}: raw secret must never leak into verdict/transcript summary/stderr`,
    )
  }
}

async function runFullStackTs(name: string, title: string, code: string): Promise<VerifyVerdict> {
  const openAttempt = createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    timeoutMs: 15_000,
    createRpcOptions: (_nonce, attempt) => {
      // Each independent attempt gets fresh server-side state, fresh RequestBroker,
      // fresh DerivedCapabilityVault, and fresh VerifyRpcServer on a real Unix socket.
      activeState = makeAttemptState(attempt)
      return {
        broker: new RequestBroker({ transportConfig: { http2: false } }),
        grant: makeGrant(),
        runId: `e2e-${name}-a${attempt}-${randomUUID().slice(0, 8)}`,
        assignmentId: `assign-${name}`,
        targetOrigins: [apiOrigin, artifactOrigin],
        compositeVerifyOptions: {
          attackerPersonas: ['dual_member', 'member_b', 'cookie_member'],
        },
      }
    },
  })
  const verdict = await verifyScript({
    candidate: { name: `${name}.ts`, runtime: 'ts', code, title },
    openAttempt,
    timeoutMs: 20_000,
    doubleReplay: true,
  })
  assertNoRawSecretsInVerdict(verdict, name)
  return verdict
}

// ============================================================================
// 1. Positive Multi-Hop Composite Workflows (Full Stack Dual Clean Replay)
// ============================================================================

test('E2E Positive 1: dual_tenant_abac + state_transition_binding + value_binding (JSON redaction, Bearer dedup, derived cookie, multi-port)', async () => {
  wireCaptures.length = 0
  const verdict = await runFullStackTs(
    'pos-dual-tenant-abac',
    'Dual-tenant cache bleed to multi-port vault ledger readback',
    `
      const apiOrigin = ctx.targetOrigins[0]!
      const artifactOrigin = ctx.targetOrigins[1]!

      // Clean ablation / pre-chain denied controls BEFORE Stage 1 mutates shared cache state
      const preDenied = await ctx.http_send('/api/v1/orgs/org_target/records', {
        as: 'dual_member', role: 'control', entityId: 'org_target',
      })
      if (preDenied.status !== 403) throw new Error('Expected pre-chain records control 403, got ' + preDenied.status)
      const preVaultDenied = await ctx.http_send(artifactOrigin + '/v1/vault/org_target/ledger', {
        as: 'dual_member', role: 'control',
      })
      if (preVaultDenied.status !== 403) throw new Error('Expected pre-chain vault control 403, got ' + preVaultDenied.status)

      // Hop 1: Prime shared permission cache; verify broker redacted secrets WITHOUT corrupting JSON
      const h1 = await ctx.http_send('/api/v1/cache/prime', {
        method: 'POST', as: 'dual_member', role: 'probe', entityId: 'org_target',
      })
      const h1Json = h1.json as Record<string, unknown>
      if (!h1Json || h1Json.nullable_token !== null || h1Json.token_count !== 4) {
        throw new Error('JSON redaction corrupted response: ' + h1.body)
      }
      if (h1Json.vault_token !== '[redacted]' || h1.headers['set-cookie'] !== '[redacted]') {
        throw new Error('Secrets were not redacted before reaching worker: ' + h1.body)
      }

      // Seal pre-prefixed "Bearer <tok>" (must NOT double-prefix as "Bearer Bearer") + Set-Cookie
      const prefixedCap = await ctx.seal_capability({
        exchange: h1, hopReceiptId: '1', slot: 'vault_bearer', jsonPath: '$.prefixed_vault_token', kind: 'bearer_token',
      })
      const cookieCap = await ctx.seal_capability({
        exchange: h1, hopReceiptId: '1', slot: 'vault_ck', cookie: 'vault_ck',
      })

      // Exercise derived cookie injection (must NOT be shadowed by cookie_member base cookie)
      const ckCheck = await ctx.http_send(artifactOrigin + '/v1/vault/cookie-check', {
        capability: cookieCap.handle, role: 'probe',
      })
      if (ckCheck.status !== 200) throw new Error('Derived cookie check failed: ' + ckCheck.status)

      // Hop 2: Access org_target records via state_transition_binding
      const h2 = await ctx.http_send('/api/v1/orgs/org_target/records', {
        as: 'dual_member', role: 'probe', entityId: 'org_target',
      })
      if (h2.status !== 200) throw new Error('Expected primed org_target 200, got ' + h2.status)
      const ticketCap = await ctx.seal_capability({
        exchange: h2, hopReceiptId: '2', slot: 'vault_ticket', jsonPath: '$.vaultTicket', kind: 'bearer_token',
      })

      // Also exercise derived bearer with a cookie-based persona (must strip base cookie to prevent shadowing)
      const shadowCheck = await ctx.http_send(artifactOrigin + '/v1/vault/org_target/ledger', {
        as: 'cookie_member', capability: { handle: prefixedCap.handle, target: 'bearer' }, role: 'control',
      })
      if (shadowCheck.status !== 200) throw new Error('Derived bearer with cookie persona failed: ' + shadowCheck.status)

      // Hop 3: Cross-origin vault ledger read on Port 2 using derived bearer from Hop 2 (OMIT as)
      const h3 = await ctx.http_send(artifactOrigin + '/v1/vault/org_target/ledger', {
        capability: { handle: ticketCap.handle, target: 'bearer' }, role: 'probe',
      })
      if (h3.status !== 200) throw new Error('Vault ledger read failed: ' + h3.status)

      const comp = await ctx.prove_composite({
        chainId: 'chain-dual-tenant-e2e',
        terminalVulnClass: 'dual_tenant_abac',
        replayMode: 'fresh_clean_replay',
        hops: [
          {
            hopId: 'hop_1', surface: 'http',
            target: { origin: apiOrigin, method: 'POST', pathAndQuery: '/api/v1/cache/prime' },
            exchangeIds: [h1.exchangeId],
            claimedDelta: 'Primed shared dual-org permission cache and received derived credentials.',
            producedCapabilities: [prefixedCap.handle, cookieCap.handle], consumedCapabilities: [],
            entityId: 'org_target',
          },
          {
            hopId: 'hop_2', surface: 'http',
            target: { origin: apiOrigin, method: 'GET', pathAndQuery: '/api/v1/orgs/org_target/records' },
            exchangeIds: [h2.exchangeId],
            claimedDelta: 'Read foreign org_target record after priming shared cache.',
            producedCapabilities: [ticketCap.handle], consumedCapabilities: [],
            entityId: 'org_target',
          },
          {
            hopId: 'hop_3', surface: 'http',
            target: { origin: artifactOrigin, method: 'GET', pathAndQuery: '/v1/vault/org_target/ledger' },
            exchangeIds: [h3.exchangeId],
            claimedDelta: 'Retrieved foreign org_target vault ledger via derived bearer token.',
            producedCapabilities: [], consumedCapabilities: [ticketCap.handle],
          },
        ],
        causalEdges: [
          { kind: 'state_transition_binding', fromHopId: 'hop_1', toHopId: 'hop_2', entityId: 'org_target', ablationExchangeIds: [preDenied.exchangeId] },
          { kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_3', capabilityHandle: ticketCap.handle },
        ],
        terminalImpact: {
          terminalHopId: 'hop_3',
          oracleFamily: 'dual_tenant_abac',
          claimedImpact: 'Unauthorized foreign-tenant ledger access via permission cache bleed and derived bearer.',
          preChainControlExchangeIds: [preDenied.exchangeId, preVaultDenied.exchangeId],
          postChainReadbackExchangeIds: [h3.exchangeId],
          oracleInput: {
            mode: 'dual_org_cache_bleed',
            actor: { actorId: 'dual_member', rolesByTenant: { org_prime: 'admin', org_target: 'member' } },
            primeTenantId: 'org_prime',
            targetTenantId: 'org_target',
            requiredRole: 'admin',
            baselineDeniedControlExchangeId: preVaultDenied.exchangeId,
            primeActionExchangeId: h1.exchangeId,
            bledAccessExchangeId: h3.exchangeId,
            observedTenantId: 'org_target',
          },
        },
      })
      if (!comp.confirmed) throw new Error('prove_composite failed: ' + comp.reason)
      return ctx.result({ title: 'Dual-tenant cache bleed to vault ledger exfil' })
    `,
  )

  assert.equal(verdict.confirmed, true, `Expected confirmed, got ${verdict.reason}: ${verdict.detail} | disagreements=${JSON.stringify(verdict.disagreements)}`)
  assert.equal(verdict.reason, 'confirmed')
  assert.deepEqual(verdict.disagreements, [])
  // Wire-level assertions across BOTH attempts: single "Bearer <raw>" (no "Bearer Bearer"),
  // no cookie shadowing when derived bearer overrides cookie_member, and clean derived cookie
  const ledgerCalls = wireCaptures.filter(
    c => c.origin === 'artifact' && c.pathAndQuery === '/v1/vault/org_target/ledger' && c.authorization === `Bearer ${MINTED_VAULT_BEARER}`,
  )
  assert.equal(ledgerCalls.length, 4, 'Expected 4 derived-bearer vault ledger calls across dual replay (2 shadow checks + 2 terminal hops)')
  for (const call of ledgerCalls) {
    assert.equal(call.authorization, `Bearer ${MINTED_VAULT_BEARER}`, 'Wire Authorization must be exact single Bearer token')
    assert.equal(call.cookie, undefined, 'Derived bearer must NOT be shadowed by cookie_member base Cookie header')
  }
  const cookieCalls = wireCaptures.filter(c => c.origin === 'artifact' && c.pathAndQuery === '/v1/vault/cookie-check')
  assert.equal(cookieCalls.length, 2, 'Expected 2 dual-replay cookie-check calls')
  for (const call of cookieCalls) {
    assert.equal(call.cookie, `vault_ck=${MINTED_VAULT_COOKIE}`, 'Wire Cookie must carry derived cookie without shadowing')
  }
})

test('E2E Positive 2: economic_conservation + value_binding (late-seal 6-req race burst, path valueDigest, fresh per-run IDs, Run 1/Run 2 winner jitter, auto-hydration)', async () => {
  wireCaptures.length = 0
  const verdict = await runFullStackTs(
    'pos-econ-race-late-seal',
    'Concurrent double settlement violating economic conservation',
    `
      import { createHash } from 'node:crypto'
      const apiOrigin = ctx.targetOrigins[0]!

      // Baseline balance read BEFORE mutating chain (role: control)
      const base = await ctx.http_send('/api/v1/accounts/acct_b/balance', { as: 'member_b', role: 'control' })
      const balBefore = Number((base.json as { balance: number }).balance)

      // Hop 1: Mint fresh per-run order ID (ord_<attempt>_<rand>)
      const h1 = await ctx.http_send('/api/v1/orders', { method: 'POST', as: 'member_b', role: 'probe' })
      const orderId = String((h1.json as { id: string }).id)
      const orderDigest = createHash('sha256').update(orderId, 'utf8').digest('hex')

      // Hop 2: Execute 6-request concurrent settlement race burst BEFORE sealing orderId (late-seal!)
      const burst = await ctx.prove_race_burst({
        requests: Array.from({ length: 6 }, () => ({
          path: '/api/v1/orders/' + orderId + '/settle-race',
          method: 'POST',
          as: 'member_b',
          role: 'probe',
        })),
        minDistinctOutcomes: 2,
        expectAllSuccess: false,
      })
      const burstIds = (burst.exchanges as Array<{ exchangeId: string }>).map(e => e.exchangeId)

      // Late seal AFTER the race burst -> triggers host-side backfill onto all 6 burst exchanges
      const orderCap = await ctx.seal_capability({
        exchange: h1, hopReceiptId: '1', slot: 'order_id', jsonPath: '$.id',
      })

      // Final balance read AFTER race burst
      const finalRead = await ctx.http_send('/api/v1/accounts/acct_b/balance', { as: 'member_b', role: 'control' })
      const balAfter = Number((finalRead.json as { balance: number }).balance)

      // Omit baselineReadbackExchangeId / finalReadbackExchangeId / actionExchangeIds from oracleInput
      // to exercise host-side auto-hydration from preChainControlExchangeIds + termHop + postChainReadbackExchangeIds!
      // Note: use static chainId (not embedding sealed orderId) due to VerifyRpcServer.handleCompositeVerify
      // recording unscrubbed verdict.chainId while returning scrubbed claim.chainId (documented engine bug).
      const comp = await ctx.prove_composite({
        chainId: 'chain-econ-race-e2e',
        terminalVulnClass: 'economic_conservation',
        replayMode: 'fresh_clean_replay',
        hops: [
          {
            hopId: 'hop_1', surface: 'http',
            target: { origin: apiOrigin, method: 'POST', pathAndQuery: '/api/v1/orders' },
            exchangeIds: [h1.exchangeId],
            claimedDelta: 'Created fresh settlement order.',
            producedCapabilities: [orderCap.handle], consumedCapabilities: [],
          },
          {
            hopId: 'hop_2', surface: 'http',
            target: { origin: apiOrigin, method: 'POST', pathAndQuery: '/api/v1/orders/' + orderId + '/settle-race' },
            exchangeIds: burstIds,
            claimedDelta: 'Concurrent 6-request race burst double-settled order.',
            producedCapabilities: [], consumedCapabilities: [orderCap.handle],
          },
        ],
        causalEdges: [
          {
            kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2',
            capabilityHandle: orderCap.handle, valueDigest: orderDigest,
          },
        ],
        terminalImpact: {
          terminalHopId: 'hop_2',
          oracleFamily: 'economic_conservation',
          claimedImpact: 'Final balance exceeds baseline plus authorized single settlement amount.',
          preChainControlExchangeIds: [base.exchangeId],
          postChainReadbackExchangeIds: [finalRead.exchangeId],
          oracleInput: {
            equation: 'balance_minting',
            balancesBefore: { acct_b: balBefore },
            balancesAfter: { acct_b: balAfter },
            authorizedDeposits: 100,
          },
        },
      })
      if (!comp.confirmed) throw new Error('prove_composite failed: ' + comp.reason)
      return ctx.result({ title: 'Concurrent double-settlement on ' + orderId })
    `,
  )

  assert.equal(verdict.confirmed, true, `Expected confirmed despite Run 1/Run 2 IDs & race jitter, got ${verdict.reason}: ${verdict.detail} | disagreements=${JSON.stringify(verdict.disagreements)}`)
  assert.equal(verdict.reason, 'confirmed')
  assert.deepEqual(verdict.disagreements, [])
  // Confirm two distinct per-run order IDs were actually hit across Attempt 1 & Attempt 2
  const settlePaths = new Set(
    wireCaptures
      .filter(c => c.origin === 'api' && c.pathAndQuery.endsWith('/settle-race'))
      .map(c => c.pathAndQuery),
  )
  assert.equal(settlePaths.size, 2, `Expected 2 distinct per-run order paths across dual replay, got ${[...settlePaths].join(', ')}`)
})

test('E2E Positive 3: cryptographic_scope_replay + derived_crypto_binding (host hmac_sign over redacted secret)', async () => {
  wireCaptures.length = 0
  const verdict = await runFullStackTs(
    'pos-crypto-scope-replay',
    'Cross-tenant webhook replay via host-derived HMAC signature',
    `
      import { createHash } from 'node:crypto'
      const apiOrigin = ctx.targetOrigins[0]!
      const payload = JSON.stringify({ action: 'credit', targetTenant: 'org_target', amount: 500 })

      // Tampered-signature control (403) rules out signature-skip decoys
      const tamperedSig = 'deadbeef00000000deadbeef00000000'
      const tamperedCtrl = await ctx.http_send('/api/v1/webhooks/apply', {
        method: 'POST', as: 'member_b', role: 'control',
        headers: { 'x-sig': tamperedSig, 'content-type': 'application/json' },
        body: payload,
      })
      if (tamperedCtrl.status !== 403) throw new Error('Expected tampered control 403, got ' + tamperedCtrl.status)

      // Hop 1: Retrieve signing config (broker redacts signing_secret in worker response)
      const h1 = await ctx.http_send('/api/v1/service/signing-config', { as: 'member_b', role: 'probe' })
      if ((h1.json as Record<string, unknown>)?.signing_secret !== '[redacted]') {
        throw new Error('Expected signing_secret redacted in worker view')
      }
      const keyCap = await ctx.seal_capability({
        exchange: h1, hopReceiptId: '1', slot: 'hmac_key', jsonPath: '$.signing_secret', kind: 'hmac_key',
      })

      // Hop 2: Host-side HMAC derivation over real unredacted secret -> replay against target tenant
      const sig = await ctx.hmac_sign({
        secretHandle: keyCap.handle, payload, alg: 'sha256', encoding: 'hex',
      })
      const h2 = await ctx.http_send('/api/v1/webhooks/apply', {
        method: 'POST', as: 'member_b', role: 'probe',
        headers: { 'x-sig': sig.signature, 'content-type': 'application/json' },
        body: payload,
      })
      if (h2.status !== 200) throw new Error('Expected signed webhook 200, got ' + h2.status)

      const tamperedDigest = createHash('sha256').update(tamperedSig, 'utf8').digest('hex')
      const validDigest = String((sig.attestation as Record<string, unknown>).signatureDigest)

      const comp = await ctx.prove_composite({
        chainId: 'chain-crypto-scope-replay-e2e',
        terminalVulnClass: 'cryptographic_scope_replay',
        replayMode: 'fresh_clean_replay',
        hops: [
          {
            hopId: 'hop_1', surface: 'http',
            target: { origin: apiOrigin, method: 'GET', pathAndQuery: '/api/v1/service/signing-config' },
            exchangeIds: [h1.exchangeId],
            claimedDelta: 'Obtained shared HMAC signing key from org_b service config.',
            producedCapabilities: [keyCap.handle], consumedCapabilities: [],
          },
          {
            hopId: 'hop_2', surface: 'webhook',
            target: { origin: apiOrigin, method: 'POST', pathAndQuery: '/api/v1/webhooks/apply' },
            exchangeIds: [sig.exchangeId, h2.exchangeId],
            claimedDelta: 'Replayed host-derived HMAC signature to apply credit in org_target.',
            producedCapabilities: [], consumedCapabilities: [keyCap.handle],
          },
        ],
        causalEdges: [
          { kind: 'derived_crypto_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sourceCapabilityId: keyCap.handle, alg: 'sha256' },
        ],
        terminalImpact: {
          terminalHopId: 'hop_2',
          oracleFamily: 'cryptographic_scope_replay',
          claimedImpact: 'Valid HMAC signature forged from org_b key accepted for org_target admin webhook.',
          preChainControlExchangeIds: [tamperedCtrl.exchangeId],
          postChainReadbackExchangeIds: [h2.exchangeId],
          oracleInput: {
            tamperedSignatureControlExchangeId: tamperedCtrl.exchangeId,
            sourceValidIssuanceExchangeId: h1.exchangeId,
            replayedAcceptanceExchangeId: h2.exchangeId,
            sourceTenant: 'org_b',
            sourceScope: 'org_b:billing',
            targetTenant: 'org_target',
            targetScope: 'org_target:admin',
            tamperedSignatureDigest: tamperedDigest,
            signatureDigest: validDigest,
            replayedSignatureDigest: validDigest,
          },
        },
      })
      if (!comp.confirmed) throw new Error('prove_composite failed: ' + comp.reason)
      return ctx.result({ title: 'Cross-tenant webhook HMAC scope replay' })
    `,
  )

  assert.equal(verdict.confirmed, true, `Expected confirmed, got ${verdict.reason}: ${verdict.detail}`)
  assert.equal(verdict.reason, 'confirmed')
  assert.deepEqual(verdict.disagreements, [])
  // Verify wire-level HMAC signatures matched the REAL unredacted secret on both attempts
  const expectedPayload = JSON.stringify({ action: 'credit', targetTenant: 'org_target', amount: 500 })
  const expectedHmac = createHmac('sha256', RAW_HMAC_SECRET).update(expectedPayload).digest('hex')
  const validWebhookCalls = wireCaptures.filter(c => c.pathAndQuery === '/api/v1/webhooks/apply' && c.xSig === expectedHmac)
  assert.equal(validWebhookCalls.length, 2, 'Expected 2 valid host-signed HMAC requests across dual replay')
})

test('E2E Positive 4: async cross-tenant exfil (cross_surface_pivot + jwt_sign + await_async queued->ready + derived_crypto_binding + async_pivot_binding + value_binding)', async () => {
  wireCaptures.length = 0
  const verdict = await runFullStackTs(
    'pos-async-cross-tenant-exfil',
    '4-hop JWT forgery and async job convergence to foreign artifact exfil',
    `
      const apiOrigin = ctx.targetOrigins[0]!
      const artifactOrigin = ctx.targetOrigins[1]!
      const corrId = 'corr_' + ctx.nonce.slice(0, 8)

      // Hop 1: Retrieve JWT signing secret (redacted in worker response, sealed in host vault)
      const h1 = await ctx.http_send('/api/v1/export/signing-meta', { as: 'member_b', role: 'probe' })
      if ((h1.json as Record<string, unknown>)?.jwt_secret !== '[redacted]') {
        throw new Error('Expected jwt_secret redacted in worker view')
      }
      const jwtKeyCap = await ctx.seal_capability({
        exchange: h1, hopReceiptId: '1', slot: 'jwt_key', jsonPath: '$.jwt_secret', kind: 'hmac_key',
      })

      // Hop 2: Forge HS256 JWT host-side via ctx.jwt_sign and enqueue cross-tenant async export job
      const mintedJwt = await ctx.jwt_sign({
        secretHandle: jwtKeyCap.handle,
        claims: { sub: 'exporter', tenant: 'org_target', scope: 'export:all' },
        alg: 'HS256',
        hopReceiptId: '2',
        slot: 'export_jwt',
      })
      const h2 = await ctx.http_send('/api/v1/exports/jobs', {
        method: 'POST',
        capability: { handle: mintedJwt.derivedHandle, target: 'bearer' },
        role: 'probe',
        correlationIds: [corrId],
        body: { targetTenant: 'org_target', correlationId: corrId },
      })
      if (h2.status !== 202) throw new Error('Expected 202 queued job, got ' + h2.status + ' ' + h2.body)
      const jobId = String((h2.json as { jobId: string }).jobId)

      // Pre-chain denied control on the exact terminal artifact route family (403 for member_b)
      const preDenied = await ctx.http_send(artifactOrigin + '/v1/artifacts/org_target/export-' + jobId + '.json', {
        as: 'member_b', role: 'control',
      })
      if (preDenied.status !== 403) throw new Error('Expected artifact control 403, got ' + preDenied.status)

      // Hop 3: Poll async job until queued -> ready via ctx.await_async
      const pol = await ctx.await_async({
        pollRequest: {
          path: '/api/v1/exports/jobs/' + jobId + '?corr=' + corrId,
          as: 'member_b', role: 'probe',
        },
        matchPredicate: { status: 200, jsonPath: '$.state', equals: 'ready' },
        triggerExchangeId: h2.exchangeId,
        correlationId: corrId,
        profile: 'fast_lab',
        intervalMs: 20,
        timeoutMs: 3000,
      })
      if (!pol.converged || !pol.exchange) throw new Error('Async poll failed to converge: ' + JSON.stringify(pol))
      if ((pol.exchange.json as Record<string, unknown>)?.download_token !== '[redacted]') {
        throw new Error('Expected download_token redacted in worker view')
      }
      const dlCap = await ctx.seal_capability({
        exchange: pol.exchange, hopReceiptId: '3', slot: 'dl_tok', jsonPath: '$.download_token', kind: 'bearer_token',
      })
      const artifactPath = String((pol.exchange.json as { artifactPath: string }).artifactPath)

      // Hop 4: Fetch final foreign-tenant business records from Port 2 using derived bearer token
      const h4 = await ctx.http_send(artifactOrigin + artifactPath, {
        capability: { handle: dlCap.handle, target: 'bearer' }, role: 'probe',
      })
      if (h4.status !== 200) throw new Error('Expected artifact 200, got ' + h4.status)

      const comp = await ctx.prove_composite({
        chainId: 'chain-async-exfil-' + jobId,
        terminalVulnClass: 'cross_surface_pivot',
        replayMode: 'fresh_clean_replay',
        hops: [
          {
            hopId: 'hop_1', surface: 'http',
            target: { origin: apiOrigin, method: 'GET', pathAndQuery: '/api/v1/export/signing-meta' },
            exchangeIds: [h1.exchangeId],
            claimedDelta: 'Extracted JWT signing key from export signing-meta.',
            producedCapabilities: [jwtKeyCap.handle], consumedCapabilities: [],
          },
          {
            hopId: 'hop_2', surface: 'webhook',
            target: { origin: apiOrigin, method: 'POST', pathAndQuery: '/api/v1/exports/jobs' },
            exchangeIds: [mintedJwt.exchangeId, h2.exchangeId],
            claimedDelta: 'Forged export-scoped HS256 JWT and queued cross-tenant async export job.',
            producedCapabilities: [mintedJwt.derivedHandle], consumedCapabilities: [jwtKeyCap.handle],
          },
          {
            hopId: 'hop_3', surface: 'async_job',
            target: { origin: apiOrigin, method: 'GET', pathAndQuery: '/api/v1/exports/jobs/' + jobId + '?corr=' + corrId },
            exchangeIds: [pol.exchangeId],
            claimedDelta: 'Async export worker converged from queued to ready and emitted download token.',
            producedCapabilities: [dlCap.handle], consumedCapabilities: [],
          },
          {
            hopId: 'hop_4', surface: 'storage',
            target: { origin: artifactOrigin, method: 'GET', pathAndQuery: artifactPath },
            exchangeIds: [h4.exchangeId],
            claimedDelta: 'Downloaded foreign org_target financial records from artifact storage.',
            producedCapabilities: [], consumedCapabilities: [dlCap.handle],
          },
        ],
        causalEdges: [
          { kind: 'derived_crypto_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sourceCapabilityId: jwtKeyCap.handle, derivedCapabilityId: mintedJwt.derivedHandle, alg: 'HS256' },
          { kind: 'async_pivot_binding', fromHopId: 'hop_2', toHopId: 'hop_3', correlationId: corrId, channel: 'poll_convergence', pollRecordId: pol.pollRecordId },
          { kind: 'value_binding', fromHopId: 'hop_3', toHopId: 'hop_4', capabilityHandle: dlCap.handle },
        ],
        terminalImpact: {
          terminalHopId: 'hop_4',
          oracleFamily: 'cross_surface_pivot',
          claimedImpact: 'Foreign org_target financial export exfiltrated across JWT, async worker, and storage surfaces.',
          preChainControlExchangeIds: [preDenied.exchangeId],
          postChainReadbackExchangeIds: [h4.exchangeId],
          // Explicit oracleInput exercises host-side hydration of CrossSurfacePivotInput (also works around
          // default dispatch bug in composite-receipt.ts:591-603 where source hop correlationToken is omitted).
          oracleInput: {
            attackerOriginPersona: { actorId: 'member_b', role: 'member', tenantId: 'org_b', isPrivilegedPreSeeded: false },
            preChainControlDeniedExchangeId: preDenied.exchangeId,
            hops: [
              { surface: 'http', role: 'trigger_write', recordExchangeId: h1.exchangeId, emittedArtifactDigest: jwtKeyCap.handle },
              { surface: 'webhook', role: 'oob_callback', recordExchangeId: h2.exchangeId, bindingKind: 'derived_crypto_binding', derivedFromCapabilityId: jwtKeyCap.handle, correlationToken: corrId },
              { surface: 'async_job', role: 'trigger_write', recordExchangeId: pol.exchangeId, bindingKind: 'async_pivot_binding', correlationToken: corrId, emittedArtifactDigest: dlCap.handle },
              { surface: 'storage', role: 'terminal_impact', recordExchangeId: h4.exchangeId, bindingKind: 'value_binding', consumedArtifactDigest: dlCap.handle },
            ],
            terminalImpact: {
              kind: 'privileged_read',
              verified: true,
              impactDigest: 'org_target-financial-export-exfil',
            },
          },
        },
      })
      if (!comp.confirmed) throw new Error('prove_composite failed: ' + comp.reason)
      return ctx.result({ title: '4-hop JWT + async export cross-tenant exfil (' + jobId + ')' })
    `,
  )

  assert.equal(verdict.confirmed, true, `Expected confirmed, got ${verdict.reason}: ${verdict.detail} | disagreements=${JSON.stringify(verdict.disagreements)}`)
  assert.equal(verdict.reason, 'confirmed')
  assert.deepEqual(verdict.disagreements, [])
  // Verify queued->ready required >= 2 polls per attempt (4 total) and artifact download carried exact raw token
  const pollCalls = wireCaptures.filter(c => c.origin === 'api' && /^\/api\/v1\/exports\/jobs\/job_/.test(c.pathAndQuery))
  assert.ok(pollCalls.length >= 4, `Expected >= 4 async poll requests (queued->ready x2 attempts), got ${pollCalls.length}`)
  const dlCalls = wireCaptures.filter(c => c.origin === 'artifact' && c.authorization === `Bearer ${RAW_DOWNLOAD_TOKEN}`)
  assert.equal(dlCalls.length, 2, 'Expected 2 authenticated artifact downloads across dual replay')
})

// ============================================================================
// 2. Negative / Adversarial Scripts (MUST Fail Closed on Full Stack!)
// ============================================================================

test('E2E Negative (a): intermediate job/export & signed-URL stubs claiming terminal impact fail closed as terminal_impact_unproven', async () => {
  // (a1) Async job creation stub claiming terminal impact without fetching artifact
  const jobStubVerdict = await runFullStackTs(
    'neg-a1-job-stub',
    'Intermediate async job stub falsely claiming cross-tenant exfil',
    `
      const apiOrigin = ctx.targetOrigins[0]!
      const preDenied = await ctx.http_send('/api/v1/exports/stub-job', { method: 'POST', role: 'control' })
      const stub = await ctx.http_send('/api/v1/exports/stub-job', { method: 'POST', as: 'member_b', role: 'probe' })
      await ctx.prove_composite({
        chainId: 'chain-neg-job-stub',
        terminalVulnClass: 'cross_tenant_export',
        replayMode: 'fresh_clean_replay',
        hops: [
          {
            hopId: 'hop_1', surface: 'async_job',
            target: { origin: apiOrigin, method: 'POST', pathAndQuery: '/api/v1/exports/stub-job' },
            exchangeIds: [stub.exchangeId],
            claimedDelta: 'Created queued export job handle.',
            producedCapabilities: [], consumedCapabilities: [],
          },
        ],
        causalEdges: [],
        terminalImpact: {
          terminalHopId: 'hop_1',
          claimedImpact: 'Claimed cross-tenant export from queued job stub only.',
          preChainControlExchangeIds: [preDenied.exchangeId],
          postChainReadbackExchangeIds: [],
        },
      })
      return ctx.result({ title: 'Queued job stub false positive attempt' })
    `,
  )
  assert.equal(jobStubVerdict.confirmed, false, 'Job stub must NOT confirm')
  assert.equal(jobStubVerdict.reason, 'oracle_failed')
  assert.equal(jobStubVerdict.rejectedBy, 'terminal_impact_unproven')

  // (a2) Signed-URL stub claiming terminal impact without downloading the target resource
  const signedUrlVerdict = await runFullStackTs(
    'neg-a2-signed-url-stub',
    'Signed URL stub falsely claiming cross-tenant disclosure',
    `
      const apiOrigin = ctx.targetOrigins[0]!
      const preDenied = await ctx.http_send('/api/v1/exports/signed-url', { method: 'POST', role: 'control' })
      const stub = await ctx.http_send('/api/v1/exports/signed-url', { method: 'POST', as: 'member_b', role: 'probe' })
      await ctx.prove_composite({
        chainId: 'chain-neg-signed-url-stub',
        terminalVulnClass: 'dual_tenant_abac',
        replayMode: 'fresh_clean_replay',
        hops: [
          {
            hopId: 'hop_1', surface: 'http',
            target: { origin: apiOrigin, method: 'POST', pathAndQuery: '/api/v1/exports/signed-url' },
            exchangeIds: [stub.exchangeId],
            claimedDelta: 'Obtained signed download URL without fetching target resource.',
            producedCapabilities: [], consumedCapabilities: [],
          },
        ],
        causalEdges: [],
        terminalImpact: {
          terminalHopId: 'hop_1',
          claimedImpact: 'Claimed cross-tenant disclosure from signed URL stub only.',
          preChainControlExchangeIds: [preDenied.exchangeId],
          postChainReadbackExchangeIds: [],
        },
      })
      return ctx.result({ title: 'Signed URL stub false positive attempt' })
    `,
  )
  assert.equal(signedUrlVerdict.confirmed, false, 'Signed-URL stub must NOT confirm')
  assert.equal(signedUrlVerdict.reason, 'oracle_failed')
  assert.equal(signedUrlVerdict.rejectedBy, 'terminal_impact_unproven')
})

test('E2E Negative (b): missing or passing (200) / post-mutation ablation control on state_transition_binding fails closed', async () => {
  // (b1) Missing ablationExchangeIds (empty array) -> schema failure
  const missingAblation = await runFullStackTs(
    'neg-b1-missing-ablation',
    'Missing ablation control on state_transition_binding',
    `
      const apiOrigin = ctx.targetOrigins[0]!
      const h1 = await ctx.http_send('/api/v1/cache/prime', { method: 'POST', as: 'dual_member', role: 'probe', entityId: 'org_target' })
      const h2 = await ctx.http_send('/api/v1/orgs/org_target/records', { as: 'dual_member', role: 'probe', entityId: 'org_target' })
      await ctx.prove_composite({
        chainId: 'chain-neg-missing-ablation',
        terminalVulnClass: 'business_logic',
        replayMode: 'fresh_clean_replay',
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin: apiOrigin, method: 'POST', pathAndQuery: '/api/v1/cache/prime' }, exchangeIds: [h1.exchangeId], claimedDelta: 'Primed cache.', producedCapabilities: [], consumedCapabilities: [], entityId: 'org_target' },
          { hopId: 'hop_2', surface: 'http', target: { origin: apiOrigin, method: 'GET', pathAndQuery: '/api/v1/orgs/org_target/records' }, exchangeIds: [h2.exchangeId], claimedDelta: 'Read records.', producedCapabilities: [], consumedCapabilities: [], entityId: 'org_target' },
        ],
        causalEdges: [
          { kind: 'state_transition_binding', fromHopId: 'hop_1', toHopId: 'hop_2', entityId: 'org_target', ablationExchangeIds: [] },
        ],
        terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Claimed cache bleed without ablation control.', preChainControlExchangeIds: [], postChainReadbackExchangeIds: [h2.exchangeId] },
      })
      return ctx.result({ title: 'Missing ablation control attempt' })
    `,
  )
  assert.equal(missingAblation.confirmed, false)
  assert.equal(missingAblation.reason, 'oracle_failed')
  assert.equal(missingAblation.rejectedBy, 'composite_schema')

  // (b2) Passing (200) ablation control on an open endpoint (Hop 2 did not depend on Hop 1!)
  const passingAblation = await runFullStackTs(
    'neg-b2-passing-ablation',
    'Passing 200 ablation control on state_transition_binding',
    `
      const apiOrigin = ctx.targetOrigins[0]!
      const openCtrl = await ctx.http_send('/api/v1/orgs/org_open/records', { as: 'dual_member', role: 'control', entityId: 'org_open' })
      const h1 = await ctx.http_send('/api/v1/cache/prime', { method: 'POST', as: 'dual_member', role: 'probe', entityId: 'org_open' })
      const h2 = await ctx.http_send('/api/v1/orgs/org_open/records', { as: 'dual_member', role: 'probe', entityId: 'org_open' })
      await ctx.prove_composite({
        chainId: 'chain-neg-passing-ablation',
        terminalVulnClass: 'business_logic',
        replayMode: 'fresh_clean_replay',
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin: apiOrigin, method: 'POST', pathAndQuery: '/api/v1/cache/prime' }, exchangeIds: [h1.exchangeId], claimedDelta: 'Primed cache.', producedCapabilities: [], consumedCapabilities: [], entityId: 'org_open' },
          { hopId: 'hop_2', surface: 'http', target: { origin: apiOrigin, method: 'GET', pathAndQuery: '/api/v1/orgs/org_open/records' }, exchangeIds: [h2.exchangeId], claimedDelta: 'Read already-open records.', producedCapabilities: [], consumedCapabilities: [], entityId: 'org_open' },
        ],
        causalEdges: [
          { kind: 'state_transition_binding', fromHopId: 'hop_1', toHopId: 'hop_2', entityId: 'org_open', ablationExchangeIds: [openCtrl.exchangeId] },
        ],
        terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Claimed state transition despite passing 200 control.', preChainControlExchangeIds: [openCtrl.exchangeId], postChainReadbackExchangeIds: [h2.exchangeId] },
      })
      return ctx.result({ title: 'Passing 200 ablation control attempt' })
    `,
  )
  assert.equal(passingAblation.confirmed, false)
  assert.equal(passingAblation.reason, 'oracle_failed')
  assert.equal(passingAblation.rejectedBy, 'composite_edge_binding')

  // (b3) Dirty-session ablation control executed AFTER Stage 1 mutated shared state
  const dirtyAblation = await runFullStackTs(
    'neg-b3-dirty-ablation',
    'Post-mutation dirty ablation control on state_transition_binding',
    `
      const apiOrigin = ctx.targetOrigins[0]!
      const h1 = await ctx.http_send('/api/v1/cache/prime', { method: 'POST', as: 'dual_member', role: 'probe', entityId: 'org_target' })
      const lateCtrl = await ctx.http_send('/api/v1/orgs/org_target/records', { as: 'dual_member', role: 'control', entityId: 'org_target' })
      const h2 = await ctx.http_send('/api/v1/orgs/org_target/records', { as: 'dual_member', role: 'probe', entityId: 'org_target' })
      await ctx.prove_composite({
        chainId: 'chain-neg-dirty-ablation',
        terminalVulnClass: 'business_logic',
        replayMode: 'fresh_clean_replay',
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin: apiOrigin, method: 'POST', pathAndQuery: '/api/v1/cache/prime' }, exchangeIds: [h1.exchangeId], claimedDelta: 'Primed cache.', producedCapabilities: [], consumedCapabilities: [], entityId: 'org_target' },
          { hopId: 'hop_2', surface: 'http', target: { origin: apiOrigin, method: 'GET', pathAndQuery: '/api/v1/orgs/org_target/records' }, exchangeIds: [h2.exchangeId], claimedDelta: 'Read records.', producedCapabilities: [], consumedCapabilities: [], entityId: 'org_target' },
        ],
        causalEdges: [
          { kind: 'state_transition_binding', fromHopId: 'hop_1', toHopId: 'hop_2', entityId: 'org_target', ablationExchangeIds: [lateCtrl.exchangeId] },
        ],
        terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Claimed state transition with dirty post-mutation control.', preChainControlExchangeIds: [lateCtrl.exchangeId], postChainReadbackExchangeIds: [h2.exchangeId] },
      })
      return ctx.result({ title: 'Dirty post-mutation ablation attempt' })
    `,
  )
  assert.equal(dirtyAblation.confirmed, false)
  assert.equal(dirtyAblation.reason, 'oracle_failed')
  assert.equal(dirtyAblation.rejectedBy, 'composite_edge_binding')
})

test('E2E Negative (c): unbound/unused value_binding handle fails closed at edge_binding', async () => {
  const verdict = await runFullStackTs(
    'neg-c-unbound-value-binding',
    'Unbound value_binding handle referencing unused capability',
    `
      const apiOrigin = ctx.targetOrigins[0]!
      const h1 = await ctx.http_send('/api/v1/orders', { method: 'POST', as: 'member_b', role: 'probe' })
      const orderId = String((h1.json as { id: string }).id)
      const unusedCap = await ctx.seal_capability({
        exchange: h1, hopReceiptId: '1', slot: 'unused_tok', jsonPath: '$.unusedToken',
      })
      const h2 = await ctx.http_send('/api/v1/orders/' + orderId + '/settle-race', {
        method: 'POST', as: 'member_b', role: 'probe',
      })
      await ctx.prove_composite({
        chainId: 'chain-neg-unbound-vb',
        terminalVulnClass: 'business_logic',
        replayMode: 'fresh_clean_replay',
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin: apiOrigin, method: 'POST', pathAndQuery: '/api/v1/orders' }, exchangeIds: [h1.exchangeId], claimedDelta: 'Created order.', producedCapabilities: [unusedCap.handle], consumedCapabilities: [] },
          { hopId: 'hop_2', surface: 'http', target: { origin: apiOrigin, method: 'POST', pathAndQuery: '/api/v1/orders/' + orderId + '/settle-race' }, exchangeIds: [h2.exchangeId], claimedDelta: 'Settled order without using unusedCap.', producedCapabilities: [], consumedCapabilities: [unusedCap.handle] },
        ],
        causalEdges: [
          { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: unusedCap.handle },
        ],
        terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Claimed value_binding via an unused sealed handle.', preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
      })
      return ctx.result({ title: 'Unbound value_binding handle attempt' })
    `,
  )
  assert.equal(verdict.confirmed, false)
  assert.equal(verdict.reason, 'oracle_failed')
  assert.equal(verdict.rejectedBy, 'composite_edge_binding')
})

test('E2E Negative (d): forged and out-of-order derived_crypto_binding both fail closed at edge_binding', async () => {
  // (d1) Forged derived_crypto_binding: script sends a decoy header WITHOUT calling ctx.hmac_sign
  const forged = await runFullStackTs(
    'neg-d1-forged-crypto',
    'Forged derived_crypto_binding without host crypto attestation',
    `
      const apiOrigin = ctx.targetOrigins[0]!
      const h1 = await ctx.http_send('/api/v1/service/signing-config', { as: 'member_b', role: 'probe' })
      const keyCap = await ctx.seal_capability({
        exchange: h1, hopReceiptId: '1', slot: 'hmac_key', jsonPath: '$.signing_secret', kind: 'hmac_key',
      })
      // Target endpoint returns 200 on decoy header, but host has NO derivedFromCapabilityId attestation!
      const h2 = await ctx.http_send('/api/v1/webhooks/decoy-accept', {
        method: 'POST', as: 'member_b', role: 'probe',
        headers: { 'x-sig': 'forged-client-side-signature-0000', 'content-type': 'application/json' },
        body: JSON.stringify({ action: 'credit' }),
      })
      await ctx.prove_composite({
        chainId: 'chain-neg-forged-crypto',
        terminalVulnClass: 'business_logic',
        replayMode: 'fresh_clean_replay',
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin: apiOrigin, method: 'GET', pathAndQuery: '/api/v1/service/signing-config' }, exchangeIds: [h1.exchangeId], claimedDelta: 'Read signing config.', producedCapabilities: [keyCap.handle], consumedCapabilities: [] },
          { hopId: 'hop_2', surface: 'webhook', target: { origin: apiOrigin, method: 'POST', pathAndQuery: '/api/v1/webhooks/decoy-accept' }, exchangeIds: [h2.exchangeId], claimedDelta: 'Sent forged signature without host derivation.', producedCapabilities: [], consumedCapabilities: [keyCap.handle] },
        ],
        causalEdges: [
          { kind: 'derived_crypto_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sourceCapabilityId: keyCap.handle, alg: 'sha256' },
        ],
        terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Claimed derived_crypto_binding without host hmac_sign.', preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
      })
      return ctx.result({ title: 'Forged derived_crypto_binding attempt' })
    `,
  )
  assert.equal(forged.confirmed, false)
  assert.equal(forged.reason, 'oracle_failed')
  assert.equal(forged.rejectedBy, 'composite_edge_binding')

  // (d2) Out-of-order derived_crypto_binding: Hop 2 HTTP request runs BEFORE key extraction & hmac_sign
  const outOfOrder = await runFullStackTs(
    'neg-d2-out-of-order-crypto',
    'Out-of-order derived_crypto_binding violating monotonic timestamps',
    `
      const apiOrigin = ctx.targetOrigins[0]!
      const payload = JSON.stringify({ action: 'credit' })
      // Execute Hop 2 webhook BEFORE Hop 1 extracts key and BEFORE hmac_sign runs!
      const earlyH2 = await ctx.http_send('/api/v1/webhooks/decoy-accept', {
        method: 'POST', as: 'member_b', role: 'probe',
        headers: { 'content-type': 'application/json' },
        body: payload,
      })
      // Tiny delay so timestamps strictly separate (earlyH2 < h1 <= sig)
      await new Promise(r => setTimeout(r, 10))
      const h1 = await ctx.http_send('/api/v1/service/signing-config', { as: 'member_b', role: 'probe' })
      const keyCap = await ctx.seal_capability({
        exchange: h1, hopReceiptId: '1', slot: 'hmac_key', jsonPath: '$.signing_secret', kind: 'hmac_key',
      })
      const lateSig = await ctx.hmac_sign({ secretHandle: keyCap.handle, payload, alg: 'sha256', encoding: 'hex' })
      await ctx.prove_composite({
        chainId: 'chain-neg-ooo-crypto',
        terminalVulnClass: 'business_logic',
        replayMode: 'fresh_clean_replay',
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin: apiOrigin, method: 'GET', pathAndQuery: '/api/v1/service/signing-config' }, exchangeIds: [h1.exchangeId], claimedDelta: 'Read signing config.', producedCapabilities: [keyCap.handle], consumedCapabilities: [] },
          { hopId: 'hop_2', surface: 'webhook', target: { origin: apiOrigin, method: 'POST', pathAndQuery: '/api/v1/webhooks/decoy-accept' }, exchangeIds: [earlyH2.exchangeId], claimedDelta: 'Early webhook preceded key extraction and signing.', producedCapabilities: [], consumedCapabilities: [keyCap.handle] },
        ],
        causalEdges: [
          { kind: 'derived_crypto_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sourceCapabilityId: keyCap.handle, alg: 'sha256' },
        ],
        terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Claimed derived_crypto_binding with out-of-order timestamps.', preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
      })
      return ctx.result({ title: 'Out-of-order derived_crypto_binding attempt (' + lateSig.exchangeId + ')' })
    `,
  )
  assert.equal(outOfOrder.confirmed, false)
  assert.equal(outOfOrder.reason, 'oracle_failed')
  assert.equal(outOfOrder.rejectedBy, 'composite_edge_binding')
})

test('E2E Negative (e): genuine Run 1 vs Run 2 route disagreement fails closed as transcript_mismatch', async () => {
  const verdict = await runFullStackTs(
    'neg-e-route-mismatch',
    'Genuine Run 1 vs Run 2 terminal route disagreement',
    `
      const apiOrigin = ctx.targetOrigins[0]!
      // Attempt 1 receives /api/v1/divergent/alpha/<id>, Attempt 2 receives /api/v1/divergent/beta/<id>
      const h1 = await ctx.http_send('/api/v1/divergent/start', { method: 'POST', as: 'member_b', role: 'probe' })
      const nextRoute = String((h1.json as { nextRoute: string }).nextRoute)
      const tokCap = await ctx.seal_capability({
        exchange: h1, hopReceiptId: '1', slot: 'div_tok', jsonPath: '$.accessToken', kind: 'bearer_token',
      })
      const preDenied = await ctx.http_send(nextRoute, { as: 'member_b', role: 'control' })
      const h2 = await ctx.http_send(nextRoute, { capability: { handle: tokCap.handle, target: 'bearer' }, role: 'probe' })
      const comp = await ctx.prove_composite({
        chainId: 'chain-neg-divergent-route',
        terminalVulnClass: 'dual_tenant_abac',
        replayMode: 'fresh_clean_replay',
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin: apiOrigin, method: 'POST', pathAndQuery: '/api/v1/divergent/start' }, exchangeIds: [h1.exchangeId], claimedDelta: 'Obtained scoped bearer token.', producedCapabilities: [tokCap.handle], consumedCapabilities: [] },
          { hopId: 'hop_2', surface: 'http', target: { origin: apiOrigin, method: 'GET', pathAndQuery: nextRoute }, exchangeIds: [h2.exchangeId], claimedDelta: 'Accessed foreign record on run-specific route.', producedCapabilities: [], consumedCapabilities: [tokCap.handle] },
        ],
        causalEdges: [
          { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: tokCap.handle },
        ],
        terminalImpact: {
          terminalHopId: 'hop_2',
          claimedImpact: 'Unauthorized cross-tenant readback on divergent terminal route.',
          preChainControlExchangeIds: [preDenied.exchangeId],
          postChainReadbackExchangeIds: [h2.exchangeId],
        },
      })
      if (!comp.confirmed) throw new Error('Expected single attempt composite to pass: ' + comp.reason)
      return ctx.result({ title: 'Divergent terminal route proof' })
    `,
  )
  assert.equal(verdict.confirmed, false, 'Divergent Run 1 vs Run 2 terminal routes MUST NOT confirm')
  assert.equal(verdict.reason, 'transcript_mismatch')
  assert.ok(verdict.disagreements.length > 0, 'Expected concrete causal fingerprint disagreement')
  assert.ok(
    verdict.attempts.every(a => a.oraclePassed),
    'Both attempts should pass individually before dual-replay causal fingerprint check rejects them',
  )
})

test('E2E Hygiene: zero v8 benchmark contamination across repository source tree', () => {
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true)
  assert.deepEqual(scan.hits, [], `Unexpected v8 benchmark contamination: ${JSON.stringify(scan.hits)}`)
})
