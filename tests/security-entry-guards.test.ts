// @fixes R3-08
/**
 * R3-08 Production-Entry Security Guard Spy Tests & Security-Optional Lint Verification.
 *
 * Drives real production entry points (NOT just internal helpers) to prove that security guards
 * execute and change outcomes, and cannot be silently bypassed by omitted optional inputs or
 * test-only safety switches:
 *   1. `browser-session-refresher` (`refreshBrowserSession` via `PersonaAuthManager.authenticatePersona`)
 *   2. `scope-origin-admission` (`assertOriginsWithinProjectScope` via `createBrowserSessionPersona` / `registerBrowserSessionPersonaFromAction`)
 *   3. `approval-lease-authority` (`authorizeStateChange` via `authorizeStateChange` with lease spy)
 *   4. `provider-stream-sanitizer` (`sanitizeProviderStream` + `scrubOutboundProviderRequest`)
 *   5. `persona-secret-needles` (`buildPersonaSecretNeedles` via `VerifyRpcServer` live RPC)
 *   6. `host-minted-oracle-stamps` (`verifyReceipt` + `HostMintedOracle`)
 *   7. `scripts/check-security-optional.ts` AST lint, test-helper import boundary, and removal-only baseline
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { newRun } from '../src/domain.ts'
import {
  authorizeStateChange,
  buildApprovalRequestFacts,
  type ApprovalLeaseAuthorizer,
} from '../src/server/approval-judge.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import {
  BrowserSessionRefreshBlockedError,
  isVerifyPathModifiedByRun,
  refreshBrowserSession,
  registerBrowserSessionPersonaFromAction,
  type BrowserSessionChromiumLaunchOptions,
  type PlaywrightBrowserLike,
  type PlaywrightRouteLike,
  type PlaywrightStorageState,
  type RefreshBrowserSessionOptions,
} from '../src/server/browser-session-auth.ts'
import { PersonaAuthManager } from '../src/server/persona-auth.ts'
import {
  assertOriginsWithinProjectScope,
  buildPersonaSecretNeedles,
  createBrowserSessionPersona,
  createProjectPersona,
  resolveRunPersonas,
} from '../src/server/persona-vault.ts'
import {
  HostMintedOracle,
  buildProofReceipt,
  verifyReceipt,
} from '../src/server/proof-receipt.ts'
import {
  sanitizeProviderStream,
  scrubOutboundProviderRequest,
} from '../src/server/provider-stream.ts'
import { assignments, brokerExchanges } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import {
  scanSecurityOptional,
  scanSourceForTestHelperImports,
  writeRemovalOnlyBaseline,
} from '../scripts/check-security-optional.ts'
import { buildTestBrowserRefreshScopePolicy } from './helpers/browser-session-test-factory.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function makeStubBrowser(capture: {
  launches: number
  routeHandlers: Array<(route: PlaywrightRouteLike) => Promise<void> | void>
  visited: string[]
}) {
  return async (_opts: BrowserSessionChromiumLaunchOptions): Promise<PlaywrightBrowserLike> => {
    capture.launches += 1
    return {
      newContext: async () => ({
        addInitScript: async () => undefined,
        route: async (_pattern, handler) => { capture.routeHandlers.push(handler) },
        routeWebSocket: async () => undefined,
        newPage: async () => ({
          goto: async url => { capture.visited.push(url) },
          waitForLoadState: async () => undefined,
          waitForTimeout: async () => undefined,
          url: () => capture.visited[capture.visited.length - 1] ?? 'about:blank',
          on: () => undefined,
          close: async () => undefined,
        }),
        storageState: async () => ({
          cookies: [{
            name: 'app_session',
            value: 'fresh_rotated_cookie_99112233',
            domain: 'app.northstar.example',
            path: '/',
            expires: -1,
            httpOnly: true,
            secure: true,
            sameSite: 'Lax',
          }],
          origins: [],
        }),
        close: async () => undefined,
      }),
      close: async () => undefined,
    }
  }
}

function rpcCall(server: VerifyRpcServer, op: string, args: Record<string, unknown> = {}): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  return new Promise((resolvePromise, reject) => {
    const body = JSON.stringify({ op, args })
    const req = httpRequest({
      socketPath: server.socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        [VERIFY_RPC_HEADER]: server.token,
        [VERIFY_NONCE_HEADER]: server.nonce,
      },
    }, res => {
      let data = ''
      res.setEncoding('utf8')
      res.on('data', chunk => { data += chunk })
      res.on('end', () => {
        try { resolvePromise(JSON.parse(data) as { ok: boolean; result?: unknown; error?: string }) } catch (err) { reject(err) }
      })
    })
    req.on('error', reject)
    req.end(body)
  })
}

async function readStreamText(stream: ReadableStream<Uint8Array>): Promise<string> {
  const reader = stream.getReader()
  const decoder = new TextDecoder()
  let out = ''
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    out += decoder.decode(value, { stream: true })
  }
  out += decoder.decode()
  return out
}

// ============================================================================
// 1. browser-session-refresher (PersonaAuthManager.authenticatePersona -> refreshBrowserSession)
// ============================================================================
describe('R3-08 entry guard: browser-session-refresher', () => {
  test('refreshBrowserSession unconditionally fails closed when scopePolicy, modifiedPaths, or verifyPathModifiedByRun is omitted', async () => {
    const capture = { launches: 0, routeHandlers: [] as Array<(route: PlaywrightRouteLike) => Promise<void> | void>, visited: [] as string[] }
    const stubLauncher = makeStubBrowser(capture)
    const state: PlaywrightStorageState = { cookies: [], origins: [] }

    // Even with allowLocalLab: true AND stub launcher AND legacy test flag, missing scopePolicy MUST fail closed.
    await assert.rejects(
      () => refreshBrowserSession({
        storageState: state,
        targetOrigin: 'http://127.0.0.1:4100',
        allowLocalLab: true,
        allowUnscopedRefreshForTest: true,
        modifiedPaths: [],
        verifyPathModifiedByRun: false,
        launchBrowser: stubLauncher,
      } as unknown as RefreshBrowserSessionOptions),
      err => err instanceof BrowserSessionRefreshBlockedError && err.code === 'SCOPE_POLICY_REQUIRED',
    )

    // Missing modifiedPaths MUST fail closed (never treated as empty).
    await assert.rejects(
      () => refreshBrowserSession({
        storageState: state,
        targetOrigin: 'https://app.northstar.example',
        scopePolicy: buildTestBrowserRefreshScopePolicy({ targetOrigin: 'https://app.northstar.example' }),
        requireScopePolicy: true,
        verifyPathModifiedByRun: false,
        launchBrowser: stubLauncher,
      } as unknown as RefreshBrowserSessionOptions),
      err => err instanceof BrowserSessionRefreshBlockedError && err.code === 'VERIFY_PATH_MODIFIED',
    )

    // Missing verifyPathModifiedByRun MUST fail closed.
    await assert.rejects(
      () => refreshBrowserSession({
        storageState: state,
        targetOrigin: 'https://app.northstar.example',
        scopePolicy: buildTestBrowserRefreshScopePolicy({ targetOrigin: 'https://app.northstar.example' }),
        requireScopePolicy: true,
        modifiedPaths: [],
        launchBrowser: stubLauncher,
      } as unknown as RefreshBrowserSessionOptions),
      err => err instanceof BrowserSessionRefreshBlockedError && err.code === 'VERIFY_PATH_MODIFIED',
    )

    // Direct isVerifyPathModifiedByRun with nullish modifiedPaths fails closed (no `if (!modifiedPaths) return false`).
    assert.throws(
      () => isVerifyPathModifiedByRun('/dashboard', 'https://app.northstar.example', undefined as unknown as readonly string[]),
      err => err instanceof BrowserSessionRefreshBlockedError && err.code === 'VERIFY_PATH_MODIFIED',
    )
    assert.equal(capture.launches, 0, 'Chromium must NEVER launch when required security inputs are missing')
  })

  test('production PersonaAuthManager.authenticatePersona enforces host-derived scopePolicy and modifiedPaths guards', async t => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-r3-08-refresher-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const store = new Store(dir, { ftsMode: 'preview' })
    t.after(() => store.close())

    const origin = 'https://app.northstar.example'
    const project = store.createProject({
      requestId: randomUUID(),
      name: 'R3-08 Entry Guard App',
      seeds: [origin],
      environment: 'public',
    })
    const persona = registerBrowserSessionPersonaFromAction(store, {
      requestId: randomUUID(),
      projectId: project.id,
      handle: 'entry-user',
      roleLabel: 'member',
      originAllowlist: [origin],
      verifyPath: '/settings',
      storageState: {
        cookies: [{
          name: 'app_session',
          value: 'seed_cookie_val_88776655',
          domain: 'app.northstar.example',
          path: '/',
          expires: -1,
          httpOnly: true,
          secure: true,
          sameSite: 'Lax',
        }],
        origins: [],
      },
    })
    const run = store.setRouteDenylist(
      store.setEnvironmentMode(
        store.run(store.createRun(newRun.parse({
          requestId: randomUUID(),
          projectId: project.id,
          goal: 'Verify production refresher entry guard',
          capabilityTier: 2,
          approvedPersonaIds: [persona.id],
        })).id),
        'staging_isolated',
      ),
      ['/admin/danger'],
    )

    const capture = { launches: 0, routeHandlers: [] as Array<(route: PlaywrightRouteLike) => Promise<void> | void>, visited: [] as string[] }
    const authManager = new PersonaAuthManager({
      launchBrowserSession: makeStubBrowser(capture),
      resolveHost: async () => ['93.184.216.34'],
    })
    t.after(() => authManager.stopAll())

    const res = await authManager.authenticatePersona(store, project.id, persona.id, undefined, run.id)
    assert.equal(res.adapterUsed, 'browser_session')
    assert.equal(capture.launches, 1)
    assert.equal(capture.routeHandlers.length, 1, 'Expected production route guard to be installed')

    let aborted = false
    await capture.routeHandlers[0]!({
      request: () => ({ url: () => `${origin}/admin/danger`, method: () => 'GET', headers: () => ({}) }),
      abort: async () => { aborted = true },
      continue: async () => undefined,
    })
    assert.equal(aborted, true, 'Host-derived ScopePolicy routeDenylist MUST abort denylisted route at production entry')

    // Record a run mutation against /settings -> next refresh via PersonaAuthManager MUST block before launching browser.
    const assignmentId = randomUUID()
    store.db.insert(assignments).values({
      id: assignmentId,
      runId: run.id,
      phase: 'investigation',
      status: 'running',
      scopeRevision: run.scopeRevision,
      goalRevision: run.goalRevision,
      sessionId: 'sess-r3-08',
      attempt: 1,
      maxTurns: 5,
      turnsUsed: 1,
      requestsUsed: 1,
      parentFactIds: [],
      sourceOrigins: [origin],
      title: 'Mutated settings',
      objective: 'Test',
      createdAt: Date.now(),
    }).run()
    store.db.insert(brokerExchanges).values({
      id: randomUUID(),
      runId: run.id,
      assignmentId,
      scopeRevision: run.scopeRevision,
      origin,
      finalOrigin: origin,
      redirectOrigins: [],
      method: 'POST',
      pathAndQuery: '/settings',
      personaHandle: 'entry-user',
      status: 200,
      mediaType: 'application/json',
      reqHeaders: {},
      respHeaders: {},
      bodyPreview: '{}',
      bodySha256: '0'.repeat(64),
      secretMatches: [],
      durationMs: 10,
      createdAt: Date.now(),
    }).run()

    await assert.rejects(
      () => authManager.authenticatePersona(store, project.id, persona.id, undefined, run.id),
      err => err instanceof BrowserSessionRefreshBlockedError && err.code === 'VERIFY_PATH_MODIFIED',
    )
    assert.equal(capture.launches, 1, 'Browser must not relaunch once verifyPath is mutated by the active run')
  })
})

// ============================================================================
// 2. scope-origin-admission (createBrowserSessionPersona -> assertOriginsWithinProjectScope)
// ============================================================================
describe('R3-08 entry guard: scope-origin-admission', () => {
  test('production persona creation invokes assertOriginsWithinProjectScope and rejects out-of-scope / PSL-sibling origins', t => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-r3-08-scope-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const store = new Store(dir, { ftsMode: 'preview' })
    t.after(() => store.close())

    const project = store.createProject({
      requestId: randomUUID(),
      name: 'Tenant A Project',
      seeds: ['https://tenant-a.vercel.app'],
      environment: 'public',
    })
    const state: PlaywrightStorageState = {
      cookies: [{
        name: 'sid',
        value: 'tenant_a_cookie_val_11223344',
        domain: 'tenant-a.vercel.app',
        path: '/',
        expires: -1,
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
      }],
      origins: [],
    }

    assert.throws(
      () => createBrowserSessionPersona(store, {
        requestId: randomUUID(),
        projectId: project.id,
        handle: 'cross-tenant',
        roleLabel: 'member',
        originAllowlist: ['https://tenant-b.vercel.app'],
        storageState: state,
      }),
      /outside the project scope/i,
    )
    assert.deepEqual(
      assertOriginsWithinProjectScope(store, project.id, ['https://tenant-a.vercel.app']),
      ['https://tenant-a.vercel.app'],
    )
  })
})

// ============================================================================
// 3. approval-lease-authority (authorizeStateChange with leaseAuthorizes spy)
// ============================================================================
describe('R3-08 entry guard: approval-lease-authority', () => {
  test('production authorizeStateChange invokes leaseAuthorizes and refuses unbounded approvedPatterns without a valid lease', () => {
    const origin = 'https://app.northstar.example'
    const facts = buildApprovalRequestFacts({
      origin,
      method: 'POST',
      pathAndQuery: '/api/v1/orders',
      personaHandle: 'alice',
      bodyPreview: '{"qty":1}',
      headers: { 'content-type': 'application/json' },
    })

    let leaseSpyCalls = 0
    const denyingLeaseSpy: ApprovalLeaseAuthorizer = () => {
      leaseSpyCalls += 1
      return false
    }

    const denied = authorizeStateChange({
      origin,
      method: 'POST',
      pathAndQuery: '/api/v1/orders',
      runId: 'run-r3-08',
      scopeRevision: 1,
      context: {
        personaHandle: 'alice',
        body: '{"qty":1}',
        headers: { 'content-type': 'application/json' },
      },
      facts,
      leaseAuthorizes: denyingLeaseSpy,
      approvedPatterns: [{
        origin,
        method: 'POST',
        pathPattern: '/api/v1/orders',
        scopeRevision: 1,
        createdAt: Date.now(),
      }],
    })

    assert.equal(leaseSpyCalls, 1, 'authorizeStateChange MUST invoke leaseAuthorizes spy')
    assert.equal(denied.approved, false, 'Expired/denied lease MUST refuse even when legacy approvedPatterns matches')

    // Missing leaseAuthorizes with only legacy approvedPatterns also fails closed!
    const missingLease = authorizeStateChange({
      origin,
      method: 'POST',
      pathAndQuery: '/api/v1/orders',
      runId: 'run-r3-08',
      scopeRevision: 1,
      context: {
        personaHandle: 'alice',
        body: '{"qty":1}',
        headers: { 'content-type': 'application/json' },
      },
      facts,
      approvedPatterns: [{
        origin,
        method: 'POST',
        pathPattern: '/api/v1/orders',
        scopeRevision: 1,
        createdAt: Date.now(),
      }],
    })
    assert.equal(missingLease.approved, false, 'Legacy approvedPatterns without live leaseAuthorizes MUST fail closed')
  })
})

// ============================================================================
// 4. provider-stream-sanitizer (scrubOutboundProviderRequest + sanitizeProviderStream)
// ============================================================================
describe('R3-08 entry guard: provider-stream-sanitizer', () => {
  test('production provider outbound & inbound stream entry points scrub primary secrets while preserving protocol frames', async () => {
    const providerKey = 'sk-provider-secret-key-r308-998877'
    const personaSecret = 'persona_bearer_r308_secret_445566'
    const secrets = [{ value: personaSecret, placeholder: '[persona:alice]' }]

    const outbound = scrubOutboundProviderRequest(
      {
        model: 'test-model',
        input: [{ role: 'user', content: `Header leaked ${personaSecret} and ${providerKey}` }],
      },
      providerKey,
      secrets,
    )
    const serializedOutbound = JSON.stringify(outbound)
    assert.equal(serializedOutbound.includes(personaSecret), false, 'Outbound provider scrubber must redact persona secret')
    assert.equal(serializedOutbound.includes(providerKey), false, 'Outbound provider scrubber must redact provider key')

    let frameSpyCount = 0
    const ssePayload = [
      'event: response.output_text.delta',
      `data: ${JSON.stringify({ type: 'response.output_text.delta', delta: `Token ${personaSecret} ok` })}`,
      '',
      'data: [DONE]',
      '',
    ].join('\n')
    const rawStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(ssePayload))
        controller.close()
      },
    })
    const sanitizedStream = sanitizeProviderStream(rawStream, providerKey, 'responses', {
      secrets,
      onFrame: () => { frameSpyCount += 1 },
    })
    const outText = await readStreamText(sanitizedStream)
    assert.ok(frameSpyCount >= 1, 'sanitizeProviderStream must process SSE frames')
    assert.equal(outText.includes(personaSecret), false, 'Inbound sanitizeProviderStream must scrub persona secret from delta text')
    assert.equal(outText.includes('event: response.output_text.delta'), true, 'SSE control line must remain intact')
    assert.equal(outText.includes('[persona:alice]'), true, 'Persona redaction placeholder must appear in sanitized frame')
  })
})

// ============================================================================
// 5. persona-secret-needles (VerifyRpcServer -> buildPersonaSecretNeedles)
// ============================================================================
describe('R3-08 entry guard: persona-secret-needles', () => {
  test('production VerifyRpcServer redacts primary persona credentials built via buildPersonaSecretNeedles on live http.send', async t => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-r3-08-needles-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const store = new Store(dir, { ftsMode: 'preview' })
    t.after(() => store.close())

    const primarySecret = 'ShortPass9!'
    const target = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ echoed: `leaked=${primarySecret}` }))
    }).listen(0, '127.0.0.1')
    t.after(() => new Promise<void>(r => { target.closeAllConnections(); target.close(() => r()) }))
    await once(target, 'listening')
    const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

    const project = store.createProject({
      requestId: randomUUID(),
      name: 'R3-08 Needle Project',
      seeds: [origin],
      environment: 'local-lab',
    })
    const created = createProjectPersona(store, {
      requestId: randomUUID(),
      projectId: project.id,
      handle: 'alice',
      roleLabel: 'member',
      authKind: 'bearer',
      secret: primarySecret,
      canaryMarkers: [],
      originAllowlist: [origin],
    })
    const personas = resolveRunPersonas(store, project.id, [created.id])
    const needles = buildPersonaSecretNeedles(personas)
    assert.ok(needles.some(n => n.value === primarySecret), 'buildPersonaSecretNeedles must include primary credential')

    const grant: Grant = {
      canRead: o => { try { return new URL(o).origin === origin } catch { return o === origin } },
      audit: () => undefined,
      allowLocalLab: true,
      maxRpsPerOrigin: 100,
      tier: 3,
      isStateChangeApproved: () => true,
      personas,
      secrets: needles,
    }
    const rpc = new VerifyRpcServer({
      broker: new RequestBroker({ transportConfig: { http2: false } }),
      grant,
      runId: `run-r3-08-needle-${randomUUID().slice(0, 8)}`,
      assignmentId: 'a-needle',
      targetOrigins: [origin],
    })
    await rpc.start()
    t.after(() => rpc.close())

    const resp = await rpcCall(rpc, 'http.send', { path: '/echo', method: 'GET', persona: 'alice' })
    assert.equal(resp.ok, true, `http.send failed: ${resp.error ?? ''}`)
    assert.equal(JSON.stringify(resp).includes(primarySecret), false, 'VerifyRpcServer MUST scrub primary persona secret from RPC responses')
  })
})

// ============================================================================
// 6. host-minted-oracle-stamps (verifyReceipt + HostMintedOracle)
// ============================================================================
describe('R3-08 entry guard: host-minted-oracle-stamps', () => {
  test('production verifyReceipt fails closed when hostMintedOracle is omitted or exchange lacks per-exchange stamp', () => {
    const origin = 'https://app.northstar.example'
    const runId = 'run-r3-08-entry-guard'
    const oracle = new HostMintedOracle()
    const ch = oracle.mintExpressionChallenge('ssti', '*', { runId, origin, method: 'GET', route: '/render', param: 'q', armRole: 'probe', exchangeId: 'p1' })
    const receipt = buildProofReceipt({
      vulnClass: 'ssti',
      target: { origin, method: 'GET', pathAndQuery: '/render?q=hi', param: 'q' },
      exchangeIds: ['c1', 'p1'],
      claimedDelta: 'Expression evaluation check',
    })

    const transcript = {
      runId,
      entries: [
        {
          exchangeId: 'c1',
          origin,
          step: {
            id: 'c1', arm: 'control' as const, method: 'GET', route: '/render', pathAndQuery: '/render?q=hi',
            status: 200, body: 'hi', actor: { handle: null, role: null, tenant: null, auth: 'unknown' as const, sameSite: null },
          },
        },
        {
          exchangeId: 'p1',
          origin,
          hostExpressionChallenge: ch,
          step: {
            id: 'p1', arm: 'probe' as const, method: 'GET', route: '/render',
            pathAndQuery: `/render?q=${encodeURIComponent(ch.expressionSyntax)}`,
            status: 200, body: `out=${ch.expectedOutput}`,
            actor: { handle: null, role: null, tenant: null, auth: 'unknown' as const, sameSite: null },
          },
        },
      ],
    }

    // Without hostMintedOracle -> MUST fail closed (confirmed: false)!
    const withoutOracle = verifyReceipt(receipt, transcript, { runId })
    assert.equal(withoutOracle.confirmed, false, 'verifyReceipt without hostMintedOracle MUST fail closed')

    // With mismatched/fresh oracle that did not mint `ch` -> MUST fail closed!
    const foreignOracle = new HostMintedOracle()
    const withForeignOracle = verifyReceipt(receipt, transcript, { hostMintedOracle: foreignOracle, runId })
    assert.equal(withForeignOracle.confirmed, false, 'verifyReceipt with foreign HostMintedOracle MUST fail closed')

    // With the real minting oracle -> confirms!
    const withMintingOracle = verifyReceipt(receipt, transcript, { hostMintedOracle: oracle, runId })
    assert.equal(withMintingOracle.confirmed, true, 'verifyReceipt with matching HostMintedOracle should confirm valid stamped probe')
  })
})

// ============================================================================
// 7. Static lint & test-helper import boundary checks (`check-security-optional.ts`)
// ============================================================================
describe('R3-08 static gate: check-security-optional.ts & test-factory isolation', () => {
  test('live repository passes check-security-optional with 0 forbidden test seams, 0 fail-open early returns, and 0 src->tests imports', () => {
    const importScan = scanSourceForTestHelperImports(REPO_ROOT)
    assert.deepEqual(importScan.hits, [], 'No file under src/** may import tests/helpers/browser-session-test-factory.ts or any tests/** module')

    const audit = scanSecurityOptional(REPO_ROOT)
    assert.equal(audit.ok, true, `check-security-optional failed:\n${audit.regressions.join('\n')}`)
    assert.equal(audit.hits.some(h => h.name === 'allowUnscopedRefreshForTest'), false, 'allowUnscopedRefreshForTest MUST be absent from src/server/**')
    assert.equal(audit.zeroToleranceHits.length, 0)
    assert.equal(audit.newBaselinedViolations.length, 0)
    assert.ok(audit.entryGuardCoverage.every(c => c.covered), 'Every registered security guard must be covered by tests/security-entry-*.test.ts')
  })

  test('check-security-optional catches new optional security inputs, forbidden test seams, fail-open returns, src->tests imports, and enforces removal-only baselines', t => {
    const tmp = mkdtempSync(join(tmpdir(), 'kovo-r3-08-lint-'))
    t.after(() => rmSync(tmp, { recursive: true, force: true }))

    mkdirSync(join(tmp, 'src/server'), { recursive: true })
    mkdirSync(join(tmp, 'scripts'), { recursive: true })
    mkdirSync(join(tmp, 'tests/helpers'), { recursive: true })

    writeFileSync(join(tmp, 'tests/helpers/browser-session-test-factory.ts'), 'export const helper = true\n')
    writeFileSync(
      join(tmp, 'src/server/bad.ts'),
      [
        "import { helper } from '../../tests/helpers/browser-session-test-factory.ts'",
        'export interface BadOpts {',
        '  scopePolicy?: { mode: string }',
        '  allowUnscopedRefreshForTest?: boolean',
        '}',
        'export function badGuard(modifiedPaths?: string[]) {',
        '  if (!modifiedPaths) return false',
        '  return Boolean(helper) && modifiedPaths.length > 0',
        '}',
      ].join('\n'),
    )

    const baselinePath = join(tmp, 'scripts/security-optional-baseline.json')
    writeFileSync(baselinePath, JSON.stringify({ version: 1, description: 'empty', baselinedKeys: [] }))

    const result = scanSecurityOptional(tmp, { baselinePath, skipEntryCoverage: true })
    assert.equal(result.ok, false)
    const kinds = new Set(result.hits.map(h => h.kind))
    assert.ok(kinds.has('optional_security_input'), 'Must catch optional scopePolicy?:')
    assert.ok(kinds.has('forbidden_test_seam'), 'Must catch allowUnscopedRefreshForTest')
    assert.ok(kinds.has('fail_open_early_return'), 'Must catch if (!modifiedPaths) return false')
    assert.ok(kinds.has('test_helper_import_in_src'), 'Must catch src/ importing tests/helpers/')

    // Removal-only baseline must refuse to add new optional_security_input entries.
    writeFileSync(
      join(tmp, 'src/server/bad.ts'),
      'export interface CleanExceptOpt { scopePolicy?: { mode: string } }\n',
    )
    assert.throws(
      () => writeRemovalOnlyBaseline(tmp, { baselinePath }),
      /Refusing to add 1 new optional security input/i,
    )

    // Removal-only baseline DOES prune keys once fixed!
    writeFileSync(baselinePath, JSON.stringify({
      version: 1,
      description: 'seeded',
      baselinedKeys: ['src/server/bad.ts::CleanExceptOpt::scopePolicy'],
    }))
    writeFileSync(
      join(tmp, 'src/server/bad.ts'),
      'export interface CleanExceptOpt { scopePolicy: { mode: string } }\n',
    )
    const pruned = writeRemovalOnlyBaseline(tmp, { baselinePath })
    assert.equal(pruned.prunedCount, 1)
    assert.deepEqual(pruned.writtenKeys, [])
  })
})
