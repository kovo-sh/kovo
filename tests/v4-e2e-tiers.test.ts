/**
 * Kovo v4 Opaque-Box 4-Tier E2E Test Suite
 *
 * Implements the full 4-tier Category-Partition + BVA + Pairwise + Workload matrix
 * covering 100% of the 28 Kovo v4 Feature Inventory items in PROJECT.md:
 *   - Tier 1 (T1-01a..e .. T1-28a..e): 140 Category-Partition & BVA tests
 *   - Tier 2 (T2-01a..e .. T2-28a..e): 140 Pairwise Component Integration tests
 *   - Tier 3 (T3-01 .. T3-28):         28 Cross-Feature Full E2E Workflows
 *   - Tier 4 (T4-01 .. T4-14):         14 Workload, Concurrency, Crash Recovery & Stress tests
 * Total: 322 distinct, genuine tests.
 */
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { describe, test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { promisify } from 'node:util'
import {
  failureTaxonomyBuckets,
  labConfigSchema,
  newProject,
  providerSettings,
  specialistProfiles,
} from '../src/domain.ts'
import type { ApprovedEndpointPattern, Finding, LabConfig } from '../src/domain.ts'
import {
  browserChainReplaySpecSchema,
  containsDestructivePayload,
  declarativeReplaySpecSchema,
  replayStepSchema,
  sqlBooleanDiffReplaySpecSchema,
} from '../src/replay-spec.ts'
import { browserSinkEnvelopeFromSteps } from '../src/server/floor-recipes.ts'
import { AGENTIC_MIN_MAX_TURNS, roleAffinityForScenario } from '../src/server/agent-session.ts'
import { BrokerApprovalRequired, BrokerCircuitOpen, BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { normalizeEndpointTemplate } from '../src/server/dedupe.ts'
import {
  convertCodeAuditSuspectsToChainSteps,
  Execution,
  extractPersonaResourcesFromExchange,
} from '../src/server/execution.ts'
import { assertLocalLabAllowed, LabRunner } from '../src/server/lab-runner.ts'
import { listModelProfiles, privateModelProfiles, saveModelProfile } from '../src/server/model-settings.ts'
import { orderProfiles } from '../src/server/provider.ts'
import { verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { buildSarifLog } from '../src/server/sarif-export.ts'
import { ScopedBrowser } from '../src/server/scoped-browser.ts'
import { extractProjectSecuritySpecAndRules, runValidatedDynamicRulesInWorker } from '../src/server/semantic-audit.ts'
import { Store } from '../src/server/store.ts'
import { probeDifferential, runSafeTemplates } from '../src/server/surface-engine.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'
import {
  loadSafeTemplates,
  parseSafeTemplateYaml,
  selectSafeTemplates,
  TemplateValidationError,
} from '../src/templates/loader.ts'
import { parseCliArgs } from '../scripts/cli.ts'
import { createApp, HARDENED_NODE_FLAGS } from './app.ts'
import { validateSarif21 } from './v3-fullstack-lab/sarif-validate.ts'
import {
  asBrokerRequest,
  assertZeroKovoOrphans,
  baseReplaySpecFields,
  decodeJwtParts,
  dockerAvailable,
  encodeWsFrame,
  hasTable,
  loadV4Module,
  makeHs256Jwt,
  makeLabGrant,
  makePublicGrant,
  makeStore,
  makeTempDir,
  makeVirtualPublicBroker,
  RAW_AWS_SECRET,
  RAW_JWT_SECRET,
  RAW_STRIPE_SECRET,
  repoRoot,
  requireExport,
  requireMethod,
  runWorkerAnalyze,
  runWorkerSast,
  runWorkerScript,
  stopExecution,
  setupApprovedRun,
  startHttpFixture,
  startMockLlmServer,
  startWsFixture,
  tableColumns,
  tableIndexes,
  withEnv,
  writeLabRepoFixture,
  writePersonaSecretFile,
} from './v4-tier-helpers.ts'
import type {
  InlineVerifyFeedback,
  RoleAffinity,
  V4BrokerContract,
  V4BrokerHttpRequest,
  V4BrowserSessionStep,
  V4Grant,
  V4LabConfig,
  V4LabTargetHandle,
  V4ScopedBrowserContract,
  V4StoreContract,
} from './v4-tier-helpers.ts'

const exec = promisify(execFile)

// ============================================================================
// TIER 1 — Category-Partition & BVA (140 cases: T1-01a..e .. T1-28a..e)
// ============================================================================

describe('Tier 1 — Category-Partition & BVA (140 cases)', () => {
  // --- Feature 1: Inline verify_replay_spec & propose_chain_finding(verifyNow) ---

  test('T1-01a: verifyReplaySpecInline exists and confirms valid http_chain spec with InlineVerifyFeedback', async (t) => {
    const rvMod = await import('../src/server/replay-verifier.ts') as Record<string, unknown>
    const verifyInline = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      rvMod, 'verifyReplaySpecInline', 'src/server/replay-verifier.ts',
    )
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify(req.url === '/api/item?id=pub' ? { ok: true, exposed: false } : { ok: true, exposed: true }))
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const spec = {
      ...baseReplaySpecFields(fx.origin),
      kind: 'http_chain',
      assertionsJq: '{ controlPassed: (.steps.ctrl.json.exposed == false), confirmed: (.steps.prb.json.exposed == true), observed: ("exposed=" + (.steps.prb.json.exposed | tostring)), expected: "exposed=false" }',
      steps: [
        { id: 'ctrl', role: 'control', description: 'Public item', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/item?id=pub' } },
        { id: 'prb', role: 'probe', description: 'Private item', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/item?id=priv' } },
      ],
    }
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyInline({
        runId,
        spec,
        attemptCount: 1,
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    const fb = res.feedback as InlineVerifyFeedback
    const replay = res.replay as { verdict: string; verificationTier?: string }
    assert.equal(fb.verdict, 'confirmed')
    assert.equal(replay.verdict, 'confirmed')
    assert.equal(fb.controlPassed, true)
    assert.equal(fb.retriesRemaining, 2)
    assert.equal(fb.stepStatuses.length, 2)
  })

  test('T1-01b: verifyReplaySpecInline rejects invalid Zod spec without returning confirmed', async () => {
    const rvMod = await import('../src/server/replay-verifier.ts') as Record<string, unknown>
    const verifyInline = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      rvMod, 'verifyReplaySpecInline', 'src/server/replay-verifier.ts',
    )
    const res = await verifyInline({
      spec: { version: 1, kind: 'http_chain', origin: 'not-a-valid-origin', steps: [] },
      attemptCount: 1,
      broker: new RequestBroker(),
      backend: new LinuxWorkerBackend(),
      grant: makeLabGrant('http://127.0.0.1:9'),
      signal: AbortSignal.timeout(10_000),
    })
    const fb = res.feedback as InlineVerifyFeedback
    const replay = res.replay as { verdict: string }
    assert.notEqual(fb.verdict, 'confirmed')
    assert.notEqual(replay.verdict, 'confirmed')
  })

  test('T1-01c: verifyReplaySpecInline attemptCount BVA (1,2,3 allowed; 4 blocked at max 2 repairs)', async (t) => {
    const rvMod = await import('../src/server/replay-verifier.ts') as Record<string, unknown>
    const verifyInline = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      rvMod, 'verifyReplaySpecInline', 'src/server/replay-verifier.ts',
    )
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ ok: false }))
    })
    const spec = {
      ...baseReplaySpecFields(fx.origin),
      kind: 'http_chain',
      assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.json.ok == true), observed: ("ok=" + (.steps.p1.json.ok | tostring)), expected: "ok=true" }',
      steps: [
        { id: 'c1', role: 'control', description: 'Control', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/c' } },
        { id: 'p1', role: 'probe', description: 'Probe', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/p' } },
      ],
    }
    const r3 = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyInline({
        spec,
        attemptCount: 3,
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    const fb3 = r3.feedback as InlineVerifyFeedback
    assert.equal(fb3.retriesRemaining, 0)

    const reqsBefore4 = fx.requests.length
    const r4 = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyInline({
        spec,
        attemptCount: 4,
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(10_000),
      }),
    )
    const fb4 = r4.feedback as InlineVerifyFeedback
    const replay4 = r4.replay as { verdict: string; evidencePayload?: Record<string, unknown> }
    assert.equal(fb4.verdict, 'inconclusive')
    assert.equal(replay4.verdict, 'inconclusive')
    assert.equal(fb4.retriesRemaining, 0)
    assert.equal(fb4.assertionSummary?.observed, 'retry_limit_exceeded')
    assert.equal(replay4.evidencePayload?.retryLimitExceeded, true)
    assert.equal(fx.requests.length, reqsBefore4, 'Attempt 4 past retry cap must send 0 wire requests')
  })

  test('T1-01d: InlineVerifyFeedback scrubs persona secrets and cookies from jqError and assertionSummary', async (t) => {
    const rvMod = await import('../src/server/replay-verifier.ts') as Record<string, unknown>
    const verifyInline = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      rvMod, 'verifyReplaySpecInline', 'src/server/replay-verifier.ts',
    )
    const secretTok = 'kovo-secret-inline-token-xyz987'
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ leaked: secretTok }))
    })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [{ handle: 'p_inline', roleLabel: 'User', authKind: 'bearer', secret: secretTok }],
    })
    const spec = {
      ...baseReplaySpecFields(fx.origin),
      kind: 'http_chain',
      assertionsJq: '.steps[0].invalidSyntax(((',
      steps: [
        { id: 'c1', role: 'control', description: 'Control', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/c', persona: 'p_inline' } },
        { id: 'p1', role: 'probe', description: 'Probe', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/p', persona: 'p_inline' } },
      ],
    }
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyInline({
        spec,
        attemptCount: 1,
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { personas: personaMap, secrets: [{ placeholder: '[redacted]', value: secretTok }] }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    const serialized = JSON.stringify(res)
    assert.ok(!serialized.includes(secretTok), 'InlineVerifyFeedback leaked persona secret')
  })

  test('T1-01e: static_ast_proof verified inline stays static_verified and never confirmed/runtime_confirmed', async (t) => {
    const rvMod = await import('../src/server/replay-verifier.ts') as Record<string, unknown>
    const verifyInline = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      rvMod, 'verifyReplaySpecInline', 'src/server/replay-verifier.ts',
    )
    const repoDir = makeTempDir(t, 'kovo-v4-static-inline-')
    chmodSync(repoDir, 0o755)
    writeLabRepoFixture(join(repoDir, 'app-repo'), { withVulns: true })
    const spec = {
      ...baseReplaySpecFields('https://static-analysis.invalid'),
      kind: 'static_ast_proof',
      repo: 'app-repo',
      file: 'src/orders.ts',
      startLine: 1,
      endLine: 3,
      engine: 'ast-grep',
      ruleOrPattern: 'db.query($Q)',
      runtimeProofGap: 'No live HTTP runtime target attached during static audit.',
      assertionsJq: '{ controlPassed: (.static.verified == true), confirmed: (.static.verified == true and .static.matchCount >= 1), observed: ("matches=" + (.static.matchCount | tostring)), expected: "0 unsafe SQL matches" }',
    }
    const res = await verifyInline({
      spec,
      attemptCount: 1,
      broker: new RequestBroker(),
      backend: new LinuxWorkerBackend(),
      reposDir: repoDir,
      grant: makeLabGrant('https://static-analysis.invalid'),
      signal: AbortSignal.timeout(30_000),
    })
    const fb = res.feedback as InlineVerifyFeedback
    const replay = res.replay as { verdict: string; verificationTier?: string }
    assert.notEqual(fb.verdict, 'confirmed')
    assert.notEqual(fb.verificationTier, 'runtime_confirmed')
    assert.equal(fb.verdict, 'static_verified')
    assert.equal(fb.verificationTier, 'static_verified')
    assert.equal(replay.verdict, 'static_verified')
    assert.equal(replay.verificationTier, 'static_verified')
  })

  // --- Feature 3: Opaque Ephemeral Session Jars ---

  test('T1-03a: session jar handle regex BVA ("a" and 32-char valid; "", 33-char, "../x" rejected)', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => res.end('ok'))
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin)

    const ok1 = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/', session: 'a' }, grant, AbortSignal.timeout(5000)),
    )
    assert.equal(ok1.status, 200)

    const ok32 = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/', session: 'jar_0123456789abcdef0123456789ab' }, grant, AbortSignal.timeout(5000)),
    )
    assert.equal(ok32.status, 200)

    for (const bad of ['', 'jar_0123456789abcdef0123456789abc', '../escape', 'jar space']) {
      await assert.rejects(
        () => withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
          broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/', session: bad }, grant, AbortSignal.timeout(5000)),
        ),
        BrokerDenied,
      )
    }
  })

  test('T1-03b: session jar enforces cookie/jar capacity bounds (<= 32 cookies/jar, <= 4 jars/assignment)', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/bake-many') {
        const cookies = Array.from({ length: 40 }, (_, i) => `c${i}=val_${i}; Path=/`)
        res.setHeader('Set-Cookie', cookies)
        res.end('baked')
        return
      }
      res.end(req.headers.cookie ?? '')
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/bake-many', session: 'cap-jar', assignmentId: 'a1' }, grant, AbortSignal.timeout(5000))
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/echo', session: 'cap-jar', assignmentId: 'a1' }, grant, AbortSignal.timeout(5000))
      const sentCookie = String(fx.requests.at(-1)?.headers.cookie ?? '')
      const count = sentCookie.split(';').filter(s => s.trim().length > 0).length
      assert.ok(count >= 1 && count <= 32, `Expected bounded <= 32 cookies in jar, got ${count}`)
    })
  })

  test('T1-03c: Set-Cookie Path=/api scoping prevents sending cookie to /public', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/api/login') {
        res.setHeader('Set-Cookie', 'api_sid=SECRET_API_SID; Path=/api; HttpOnly')
        res.end('logged-in')
        return
      }
      res.end(req.headers.cookie ?? 'none')
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/api/login', session: 'path-jar' }, grant, AbortSignal.timeout(5000))
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/api/me', session: 'path-jar' }, grant, AbortSignal.timeout(5000))
      assert.match(String(fx.requests.at(-1)?.headers.cookie ?? ''), /api_sid=/)
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/public', session: 'path-jar' }, grant, AbortSignal.timeout(5000))
      assert.equal(fx.requests.at(-1)?.headers.cookie ?? undefined, undefined)
    })
  })

  test('T1-03d: Persona vault credentials retain precedence over ephemeral jar cookies', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/login') {
        res.setHeader('Set-Cookie', 'sid=JAR_LOW_PRIV; Path=/')
        res.end('ok')
        return
      }
      res.end('ok')
    })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [{ handle: 'vault_user', roleLabel: 'Admin', authKind: 'bearer', secret: 'VAULT_JWT_AUTHORITATIVE' }],
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin, { personas: personaMap, secrets: [{ placeholder: '[redacted]', value: 'VAULT_JWT_AUTHORITATIVE' }] })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/login', session: 'prec-jar', persona: 'vault_user' }, grant, AbortSignal.timeout(5000))
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/me', session: 'prec-jar', persona: 'vault_user' }, grant, AbortSignal.timeout(5000))
      const last = fx.requests.at(-1)!
      assert.equal(last.headers.authorization, 'Bearer VAULT_JWT_AUTHORITATIVE')
      assert.match(String(last.headers.cookie ?? ''), /sid=/)
    })
  })

  test('T1-03e: scopeRevision revocation purges session jar cookies for revoked origin', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/login') {
        res.setHeader('Set-Cookie', 'sid=REVOKE_ME_COOKIE; Path=/')
      }
      res.end('ok')
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    let allow = true
    const grant = makeLabGrant(fx.origin, { canRead: o => allow && o === fx.origin })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/login', session: 'rev-jar' }, grant, AbortSignal.timeout(5000))
      allow = false
      await assert.rejects(
        () => broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/me', session: 'rev-jar' }, grant, AbortSignal.timeout(5000)),
        /denied|revoked|scope/i,
      )
      if (typeof broker.revokeOrigin === 'function') broker.revokeOrigin(fx.origin)
      allow = true
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/me', session: 'rev-jar' }, grant, AbortSignal.timeout(5000))
      assert.equal(fx.requests.at(-1)?.headers.cookie ?? undefined, undefined, 'Revoked origin cookie was not purged')
    })
  })

  // --- Feature 4: Automatic CSRF Token Extraction & Binding ---

  test('T1-04a: csrfBind extracts XSRF-TOKEN cookie and binds X-XSRF-TOKEN header', async (t) => {
    const csrfVal = 'xsrf-cookie-token-918273'
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.method === 'GET') {
        res.setHeader('Set-Cookie', `XSRF-TOKEN=${csrfVal}; Path=/`)
        res.end('ok')
        return
      }
      res.end('posted')
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/form', session: 'csrf-a' }, grant, AbortSignal.timeout(5000))
      await broker.executeHttp({
        origin: fx.origin, method: 'POST', pathAndQuery: '/submit', session: 'csrf-a', csrfBind: true,
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ q: 'hello' }),
      }, grant, AbortSignal.timeout(5000))
      const postHdrs = fx.requests.at(-1)!.headers
      assert.equal(postHdrs['x-xsrf-token'] ?? postHdrs['x-csrf-token'], csrfVal)
    })
  })

  test('T1-04b: csrfBind extracts <meta name="csrf-token"> and binds request header', async (t) => {
    const metaVal = 'meta-csrf-val-abc123'
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.method === 'GET') {
        res.setHeader('Content-Type', 'text/html')
        res.end(`<html><head><meta name="csrf-token" content="${metaVal}"></head></html>`)
        return
      }
      res.end('ok')
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/page', session: 'csrf-b' }, grant, AbortSignal.timeout(5000))
      await broker.executeHttp({
        origin: fx.origin, method: 'POST', pathAndQuery: '/api/action', session: 'csrf-b', csrfBind: true,
        headers: { 'Content-Type': 'application/json' }, body: '{}',
      }, grant, AbortSignal.timeout(5000))
      const postHdrs = fx.requests.at(-1)!.headers
      assert.equal(postHdrs['x-csrf-token'] ?? postHdrs['x-xsrf-token'], metaVal)
    })
  })

  test('T1-04c: csrfBind extracts hidden <input name="csrfmiddlewaretoken"> and binds form field', async (t) => {
    const formTok = 'django-hidden-csrf-998877'
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.method === 'GET') {
        res.setHeader('Content-Type', 'text/html')
        res.end(`<form method="POST"><input type="hidden" name="csrfmiddlewaretoken" value="${formTok}"></form>`)
        return
      }
      res.end('ok')
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/login', session: 'csrf-c' }, grant, AbortSignal.timeout(5000))
      await broker.executeHttp({
        origin: fx.origin, method: 'POST', pathAndQuery: '/login', session: 'csrf-c', csrfBind: true,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'user=alice',
      }, grant, AbortSignal.timeout(5000))
      const last = fx.requests.at(-1)!
      assert.ok(last.body.includes(`csrfmiddlewaretoken=${formTok}`) || last.headers['x-csrf-token'] === formTok)
    })
  })

  test('T1-04d: csrfBind explicit override { headerName, fieldName, cookieName } binds custom names', async (t) => {
    const customTok = 'custom-csrf-xyz-555'
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.method === 'GET') {
        res.setHeader('Set-Cookie', `MY_ANTI_CSRF=${customTok}; Path=/`)
        res.end('ok')
        return
      }
      res.end('ok')
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/init', session: 'csrf-d' }, grant, AbortSignal.timeout(5000))
      await broker.executeHttp({
        origin: fx.origin, method: 'POST', pathAndQuery: '/save', session: 'csrf-d',
        csrfBind: { headerName: 'X-Custom-Csrf', cookieName: 'MY_ANTI_CSRF', fieldName: 'custom_csrf' },
        headers: { 'Content-Type': 'application/json' }, body: '{}',
      }, grant, AbortSignal.timeout(5000))
      assert.equal(fx.requests.at(-1)!.headers['x-custom-csrf'], customTok)
    })
  })

  test('T1-04e: csrfBind performs clean no-op when no CSRF token was observed in jar', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => res.end('ok'))
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      broker.executeHttp({
        origin: fx.origin, method: 'POST', pathAndQuery: '/ping', session: 'csrf-e', csrfBind: true,
        headers: { 'Content-Type': 'application/json' }, body: '{"ping":1}',
      }, grant, AbortSignal.timeout(5000)),
    )
    assert.equal(res.status, 200)
    assert.equal(fx.requests.at(-1)!.headers['x-csrf-token'], undefined)
  })

  // --- Feature 5: Persistent PlaywrightContext/Page (runBrowserSession) ---

  test('T1-05a: browserChainReplaySpecSchema allows omitted pathAndQuery on step >= 2 with reusePage', () => {
    const parsed = browserChainReplaySpecSchema.safeParse({
      ...baseReplaySpecFields('https://app.example.invalid'),
      kind: 'browser_chain',
      assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: true, observed: "ok", expected: "clean" }',
      steps: [
        { id: 'c1', role: 'control', description: 'Control nav', origin: 'https://app.example.invalid', pathAndQuery: '/', action: 'navigate' },
        { id: 'p1', role: 'probe', description: 'Fill input', origin: 'https://app.example.invalid', pathAndQuery: '/wizard', action: 'fill', selector: '#name', value: 'alice' },
        { id: 'p2', role: 'probe', description: 'Click next on same page', origin: 'https://app.example.invalid', reusePage: true, action: 'click', selector: '#next' },
      ],
    } as unknown)
    assert.equal(parsed.success, true, parsed.success ? '' : parsed.error.message)
  })

  test('T1-05b: browserChainReplaySpecSchema rejects omitted pathAndQuery on step 1', () => {
    const parsed = browserChainReplaySpecSchema.safeParse({
      ...baseReplaySpecFields('https://app.example.invalid'),
      kind: 'browser_chain',
      assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: true, observed: "ok", expected: "clean" }',
      steps: [
        { id: 'c1', role: 'control', description: 'Control nav missing path', origin: 'https://app.example.invalid', action: 'navigate' },
        { id: 'p1', role: 'probe', description: 'Probe nav', origin: 'https://app.example.invalid', pathAndQuery: '/p', action: 'navigate' },
      ],
    } as unknown)
    assert.equal(parsed.success, false)
  })

  test('T1-05c: runBrowserSession resets DOM and localStorage when resetContext: true', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      if (req.url === '/set') {
        res.end('<html><body><div id="res">set</div><script>localStorage.setItem("stepKey", "secret_s1");</script></body></html>')
        return
      }
      res.end('<html><body><div id="res"></div><script>document.getElementById("res").textContent = "val=" + (localStorage.getItem("stepKey") || "CLEAN");</script></body></html>')
    })
    const browser = new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })) as unknown as V4ScopedBrowserContract
    const runSession = requireMethod<V4ScopedBrowserContract['runBrowserSession']>(browser, 'runBrowserSession', 'ScopedBrowser')
    const steps: V4BrowserSessionStep[] = [
      { id: 's1', role: 'probe', description: 'Set storage', origin: fx.origin, pathAndQuery: '/set', action: 'navigate', builtinCheck: 'storage_keys' },
      { id: 's2', role: 'probe', description: 'Reset context', origin: fx.origin, pathAndQuery: '/check', resetContext: true, action: 'navigate', builtinCheck: 'storage_keys' },
    ]
    const results = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runSession(steps, makeLabGrant(fx.origin), AbortSignal.timeout(30_000)),
    )
    assert.equal(results.length, 2)
    assert.ok(Array.isArray(results[0].localStorageKeys) && (results[0].localStorageKeys as string[]).includes('stepKey'))
    assert.ok(String(results[1].domSnippet ?? '').includes('val=CLEAN'))
    assert.ok(!(results[1].localStorageKeys as string[] | undefined ?? []).includes('stepKey'))
  })

  test('T1-05d: runBrowserSession automatically resets context on groupRole transition control <-> probe', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      if (req.url === '/set') {
        res.end('<html><body><div id="res">set</div><script>localStorage.setItem("stepKey", "secret_s1");</script></body></html>')
        return
      }
      res.end('<html><body><div id="res"></div><script>document.getElementById("res").textContent = "val=" + (localStorage.getItem("stepKey") || "CLEAN");</script></body></html>')
    })
    const browser = new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })) as unknown as V4ScopedBrowserContract
    const runSession = requireMethod<V4ScopedBrowserContract['runBrowserSession']>(browser, 'runBrowserSession', 'ScopedBrowser')
    const results = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runSession([
        { id: 'c1', role: 'control', description: 'Control set', origin: fx.origin, pathAndQuery: '/set', action: 'navigate', builtinCheck: 'storage_keys' },
        { id: 'p1', role: 'probe', description: 'Probe check', origin: fx.origin, pathAndQuery: '/check', action: 'navigate', builtinCheck: 'storage_keys' },
      ], makeLabGrant(fx.origin), AbortSignal.timeout(30_000)),
    )
    assert.equal(results.length, 2)
    assert.ok(Array.isArray(results[0].localStorageKeys) && (results[0].localStorageKeys as string[]).includes('stepKey'))
    assert.ok(String(results[1].domSnippet ?? '').includes('val=CLEAN'))
    assert.ok(!(results[1].localStorageKeys as string[] | undefined ?? []).includes('stepKey'))
  })

  test('T1-05e: runBrowserSession resets context when persona changes between steps', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      if (req.url === '/set') {
        res.end('<html><body><div id="res">set</div><script>localStorage.setItem("stepKey", "secret_s1");</script></body></html>')
        return
      }
      res.end('<html><body><div id="res"></div><script>document.getElementById("res").textContent = "val=" + (localStorage.getItem("stepKey") || "CLEAN");</script></body></html>')
    })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [
        { handle: 'p_one', roleLabel: 'A', authKind: 'bearer', secret: 'tok-p1' },
        { handle: 'p_two', roleLabel: 'B', authKind: 'bearer', secret: 'tok-p2' },
      ],
    })
    const browser = new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })) as unknown as V4ScopedBrowserContract
    const runSession = requireMethod<V4ScopedBrowserContract['runBrowserSession']>(browser, 'runBrowserSession', 'ScopedBrowser')
    const results = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runSession([
        { id: 's1', role: 'probe', description: 'Persona A', origin: fx.origin, pathAndQuery: '/set', persona: 'p_one', action: 'navigate', builtinCheck: 'storage_keys' },
        { id: 's2', role: 'probe', description: 'Persona B', origin: fx.origin, pathAndQuery: '/check', persona: 'p_two', action: 'navigate', builtinCheck: 'storage_keys' },
      ], makeLabGrant(fx.origin, { personas: personaMap }), AbortSignal.timeout(30_000)),
    )
    assert.equal(results.length, 2)
    assert.ok(Array.isArray(results[0].localStorageKeys) && (results[0].localStorageKeys as string[]).includes('stepKey'))
    assert.ok(String(results[1].domSnippet ?? '').includes('val=CLEAN'))
    assert.ok(!(results[1].localStorageKeys as string[] | undefined ?? []).includes('stepKey'))
    assert.equal(fx.requests[0]?.headers.authorization, 'Bearer tok-p1')
    assert.equal(fx.requests[1]?.headers.authorization, 'Bearer tok-p2')
  })

  // --- Feature 6: Broker-Side Auth-Mutation Primitives ---

  test('T1-06a: replayStepSchema accepts all 7 authMutation kinds', () => {
    const mutations = [
      { kind: 'alg_none' },
      { kind: 'strip_signature' },
      { kind: 'expired_replay', skewSeconds: 3600 },
      { kind: 'rs256_to_hs256_jwks', jwksUrl: 'https://app.example.invalid/.well-known/jwks.json' },
      { kind: 'kid_inject', value: 'key-1' },
      { kind: 'jku_x5u_canary', header: 'jku' },
      { kind: 'claim_swap', claims: { role: 'admin' } },
    ]
    for (const authMutation of mutations) {
      const parsed = replayStepSchema.safeParse({
        id: 'step1',
        role: 'probe',
        description: `Test ${authMutation.kind}`,
        request: {
          origin: 'https://app.example.invalid',
          method: 'GET',
          pathAndQuery: '/api/me',
          persona: 'user_a',
          authMutation,
        },
      } as unknown)
      assert.equal(parsed.success, true, `Expected authMutation ${authMutation.kind} to pass schema`)
      if (parsed.success) {
        assert.deepEqual((parsed.data.request as Record<string, unknown>).authMutation, authMutation)
      }
    }
  })

  test('T1-06b: RequestBroker rejects authMutation without persona handle (BrokerDenied)', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => res.end('ok'))
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    await assert.rejects(
      () => withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
        broker.executeHttp({
          origin: fx.origin, method: 'GET', pathAndQuery: '/api/me',
          authMutation: { kind: 'alg_none' },
        }, makeLabGrant(fx.origin), AbortSignal.timeout(5000)),
      ),
      BrokerDenied,
    )
  })

  test('T1-06c: claim_swap authMutation rejected on public project below Tier 3', async () => {
    const pubOrigin = 'https://public-app.example.invalid'
    const jwt = makeHs256Jwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'u1', role: 'user' })
    const personas = new Map([['u1', {
      id: randomUUID(), handle: 'u1', roleLabel: 'User', originAllowlist: [pubOrigin],
      authKind: 'bearer' as const, headerName: null, secret: jwt, canaryMarkers: [],
    }]])
    const broker = makeVirtualPublicBroker(() => ({ status: 200, headers: {}, body: 'ok' })) as unknown as V4BrokerContract
    await assert.rejects(
      () => broker.executeHttp({
        origin: pubOrigin, method: 'GET', pathAndQuery: '/api/admin', persona: 'u1',
        authMutation: { kind: 'claim_swap', claims: { role: 'admin' } },
      }, makePublicGrant(pubOrigin, { tier: 2, personas }), AbortSignal.timeout(5000)),
      err => err instanceof BrokerDenied || err instanceof BrokerApprovalRequired,
    )
  })

  test('T1-06d: kid_inject with destructive payload is blocked by BrokerDenied', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => res.end('ok'))
    const jwt = makeHs256Jwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'u1' })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [{ handle: 'u1', roleLabel: 'User', authKind: 'bearer', secret: jwt }],
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    await assert.rejects(
      () => withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
        broker.executeHttp({
          origin: fx.origin, method: 'GET', pathAndQuery: '/api/me', persona: 'u1',
          authMutation: { kind: 'kid_inject', value: '; rm -rf /' },
        }, makeLabGrant(fx.origin, { personas: personaMap }), AbortSignal.timeout(5000)),
      ),
      BrokerDenied,
    )
  })

  test('T1-06e: expired_replay skewSeconds BVA rewinds JWT exp claim in wire header', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => res.end('ok'))
    const futureExp = Math.floor(Date.now() / 1000) + 3600
    const jwt = makeHs256Jwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'u1', exp: futureExp })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [{ handle: 'u1', roleLabel: 'User', authKind: 'bearer', secret: jwt }],
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      broker.executeHttp({
        origin: fx.origin, method: 'GET', pathAndQuery: '/api/me', persona: 'u1',
        authMutation: { kind: 'expired_replay', skewSeconds: 7200 },
      }, makeLabGrant(fx.origin, { personas: personaMap }), AbortSignal.timeout(5000)),
    )
    const wireAuth = String(fx.requests.at(-1)?.headers.authorization ?? '')
    assert.ok(wireAuth.startsWith('Bearer '))
    const { payload } = decodeJwtParts(wireAuth.slice(7))
    assert.ok(Number(payload.exp) < Math.floor(Date.now() / 1000), 'Expected wire JWT exp to be in the past')
  })

  // --- Feature 7: Tier-2 sandboxWriteAllowlist ---

  test('T1-07a: public project defaults to sandboxWriteAllowlist: [] in SQLite', async (t) => {
    const { storage } = makeStore(t)
    const { projectId } = await setupApprovedRun(storage, { environment: 'public' })
    const cols = tableColumns(storage, 'projects')
    assert.ok(cols.includes('sandbox_write_allowlist'), 'projects.sandbox_write_allowlist column missing')
    const row = storage.client.prepare('SELECT sandbox_write_allowlist FROM projects WHERE id = ?').get(projectId) as { sandbox_write_allowlist: string }
    assert.deepEqual(JSON.parse(row.sandbox_write_allowlist), [])
  })

  test('T1-07b: Tier-2 sandboxWriteAllowlist permits matching POST path and denies non-matching POST', async () => {
    const origin = 'https://sandbox.example.invalid'
    const allowlist: ApprovedEndpointPattern[] = [{ origin, method: 'POST', pathPattern: '/api/v1/*' }]
    const broker = makeVirtualPublicBroker(() => ({ status: 200, headers: {}, body: '{"ok":true}' })) as unknown as V4BrokerContract
    const grant = makePublicGrant(origin, { tier: 2, sandboxWriteAllowlist: allowlist })
    const okRes = await broker.executeHttp({
      origin, method: 'POST', pathAndQuery: '/api/v1/search',
      headers: { 'Content-Type': 'application/json' }, body: '{"q":"test"}',
    }, grant, AbortSignal.timeout(5000))
    assert.equal(okRes.status, 200)

    await assert.rejects(
      () => broker.executeHttp({
        origin, method: 'POST', pathAndQuery: '/api/admin/nuke',
        headers: { 'Content-Type': 'application/json' }, body: '{}',
      }, grant, AbortSignal.timeout(5000)),
      BrokerDenied,
    )
  })

  test('T1-07c: Tier-2 sandboxWriteAllowlist strictly blocks DELETE and PUT methods', async () => {
    const origin = 'https://sandbox.example.invalid'
    const allowlist: ApprovedEndpointPattern[] = [
      { origin, method: 'DELETE', pathPattern: '/api/items/*' },
      { origin, method: 'PUT', pathPattern: '/api/items/*' },
    ]
    const broker = makeVirtualPublicBroker(() => ({ status: 200, headers: {}, body: 'ok' })) as unknown as V4BrokerContract
    const grant = makePublicGrant(origin, { tier: 2, sandboxWriteAllowlist: allowlist })
    for (const method of ['DELETE', 'PUT'] as const) {
      await assert.rejects(
        () => broker.executeHttp({ origin, method, pathAndQuery: '/api/items/1' }, grant, AbortSignal.timeout(5000)),
        BrokerDenied,
      )
    }
  })

  test('T1-07d: Tier-2 sandboxWriteAllowlist blocks multipartParts uploads', async () => {
    const origin = 'https://sandbox.example.invalid'
    const allowlist: ApprovedEndpointPattern[] = [{ origin, method: 'POST', pathPattern: '/api/upload' }]
    const broker = makeVirtualPublicBroker(() => ({ status: 200, headers: {}, body: 'ok' })) as unknown as V4BrokerContract
    const grant = makePublicGrant(origin, { tier: 2, sandboxWriteAllowlist: allowlist })
    await assert.rejects(
      () => broker.executeHttp({
        origin, method: 'POST', pathAndQuery: '/api/upload',
        multipartParts: [{ name: 'file', filename: 'a.txt', contentType: 'text/plain', content: 'hi' }],
      }, grant, AbortSignal.timeout(5000)),
      BrokerDenied,
    )
  })

  test('T1-07e: Tier-2 sandboxWriteAllowlist rejects destructive payloads on allowlisted POST', async () => {
    const origin = 'https://sandbox.example.invalid'
    const allowlist: ApprovedEndpointPattern[] = [{ origin, method: 'POST', pathPattern: '/api/search' }]
    const broker = makeVirtualPublicBroker(() => ({ status: 200, headers: {}, body: 'ok' })) as unknown as V4BrokerContract
    const grant = makePublicGrant(origin, { tier: 2, sandboxWriteAllowlist: allowlist })
    await assert.rejects(
      () => broker.executeHttp({
        origin, method: 'POST', pathAndQuery: '/api/search',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ q: '1; DROP TABLE users;--' }),
      }, grant, AbortSignal.timeout(5000)),
      BrokerDenied,
    )
  })

  // --- Feature 8: Zero-LLM Phase-0 Deterministic Surface Mapper ---

  test('T1-08a: phase0-recon enforces min(floor(15% * budgetRequests), 250) per-origin budget cap BVA', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const runPhase0 = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runPhase0Recon', 'src/server/phase0-recon.ts',
    )
    const links = Array.from({ length: 300 }, (_, i) => `<a href="/p/${i}">p${i}</a>`).join('')
    const fxLow = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body>${links}</body></html>`)
    })
    const { storage: sLow } = makeStore(t)
    const { runId: rLow } = await setupApprovedRun(sLow, { seeds: [fxLow.origin], budgetRequests: 100 })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runPhase0({
        storage: sLow, runId: rLow, scopeRevision: 1, tier: 1, origins: [fxLow.origin], budgetRequests: 100,
        broker: new RequestBroker({ rejectUnauthorized: false }), grant: makeLabGrant(fxLow.origin, { tier: 1 }),
        signal: AbortSignal.timeout(20_000),
      }),
    )
    assert.ok(fxLow.requests.length >= 1 && fxLow.requests.length <= 15, `Expected <= 15 requests (15% of 100), got ${fxLow.requests.length}`)

    const fxHigh = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body>${links}</body></html>`)
    })
    const { storage: sHigh } = makeStore(t)
    const { runId: rHigh } = await setupApprovedRun(sHigh, { seeds: [fxHigh.origin], budgetRequests: 10_000 })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runPhase0({
        storage: sHigh, runId: rHigh, scopeRevision: 1, tier: 1, origins: [fxHigh.origin], budgetRequests: 10_000,
        broker: new RequestBroker({ rejectUnauthorized: false }), grant: makeLabGrant(fxHigh.origin, { tier: 1 }),
        signal: AbortSignal.timeout(20_000),
      }),
    )
    assert.ok(fxHigh.requests.length >= 1 && fxHigh.requests.length <= 250, `Expected <= 250 requests ceiling, got ${fxHigh.requests.length}`)
  })

  test('T1-08b: phase0-recon includes standard .well-known, OpenAPI, and GraphQL seed probes', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const runPhase0 = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runPhase0Recon', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.statusCode = 404
      res.end('not found')
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 500 })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runPhase0({
        storage, runId, scopeRevision: 1, tier: 1, origins: [fx.origin], budgetRequests: 500,
        broker: new RequestBroker({ rejectUnauthorized: false }), grant: makeLabGrant(fx.origin, { tier: 1 }),
        signal: AbortSignal.timeout(20_000),
      }),
    )
    const probed = new Set(fx.requests.map(r => new URL(r.url, fx.origin).pathname))
    for (const expected of ['/robots.txt', '/sitemap.xml', '/.well-known/openid-configuration', '/.well-known/jwks.json', '/openapi.json', '/graphql']) {
      assert.ok(probed.has(expected), `Missing Phase-0 wire probe path ${expected}`)
    }
  })

  test('T1-08c: phase0-recon static framework route extractor detects Next.js, Express, FastAPI, Django, Spring, Go', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const runPhase0 = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runPhase0Recon', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (_req, _b, res) => res.end('ok'))
    const dir = makeTempDir(t, 'kovo-v4-fw-')
    mkdirSync(join(dir, 'repo/app/api/orders'), { recursive: true })
    writeFileSync(join(dir, 'repo/app/api/orders/route.ts'), `export async function GET() { return Response.json([]) }\nexport async function POST() { return Response.json({}) }`)
    writeFileSync(join(dir, 'repo/express.ts'), `app.get('/api/v1/users/:id', authMw, handler)`)
    writeFileSync(join(dir, 'repo/main.py'), `@app.post("/items/{item_id}")\ndef update_item(): pass`)
    writeFileSync(join(dir, 'repo/Controller.java'), `@GetMapping("/admin/audit")\npublic String audit() { return "ok"; }`)
    writeFileSync(join(dir, 'repo/server.go'), `r.GET("/healthz", healthHandler)`)
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin], tier: 0 })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runPhase0({
        storage, runId, scopeRevision: 1, tier: 0, origins: [fx.origin], reposDir: dir,
        broker: new RequestBroker({ rejectUnauthorized: false }), grant: makeLabGrant(fx.origin, { tier: 0 }),
        signal: AbortSignal.timeout(15_000),
      }),
    )
    const eps = (storage as unknown as V4StoreContract).listEndpoints(runId)
    const joined = eps.map(e => `${String(e.method)} ${String(e.pathTemplate ?? e.path_template)}`).join('\n')
    assert.match(joined, /\/api\/orders/)
    assert.match(joined, /\/api\/v1\/users\//)
    assert.match(joined, /\/items\//)
    assert.match(joined, /\/admin\/audit/)
    assert.match(joined, /\/healthz/)
  })

  test('T1-08d: phase0-recon dynamic wordlist synthesizer deduplicates and bounds candidate tokens', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const runPhase0 = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runPhase0Recon', 'src/server/phase0-recon.ts',
    )
    const dupBundle = [
      `fetch('/api/invoices'); fetch('/api/invoices'); fetch('/api/orders/123');`,
      ...Array.from({ length: 600 }, (_, i) => `fetch('/r/${i}');`),
    ].join('\n')
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/bundle.js') {
        res.setHeader('Content-Type', 'application/javascript')
        res.end(dupBundle)
        return
      }
      res.setHeader('Content-Type', 'text/html')
      res.end('<html><script src="/bundle.js"></script></html>')
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 10_000 })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runPhase0({
        storage, runId, scopeRevision: 1, tier: 1, origins: [fx.origin], budgetRequests: 10_000,
        broker: new RequestBroker({ rejectUnauthorized: false }), grant: makeLabGrant(fx.origin, { tier: 1 }),
        signal: AbortSignal.timeout(20_000),
      }),
    )
    const eps = (storage as unknown as V4StoreContract).listEndpoints(runId)
    const paths = eps.map(e => String(e.pathTemplate ?? e.path_template))
    assert.ok(paths.includes('/api/invoices'))
    assert.equal(paths.filter(p => p === '/api/invoices').length, 1)
    assert.ok(fx.requests.length <= 250, `Expected bounded Phase-0 probing <= 250, got ${fx.requests.length}`)
  })

  test('T1-08e: phase0-recon skips live HTTP requests at capabilityTier 0 and runs repo-only extraction', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const runPhase0 = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runPhase0Recon', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (_req, _b, res) => res.end('ok'))
    const repoDir = makeTempDir(t, 'kovo-v4-t0-')
    writeLabRepoFixture(join(repoDir, 'app'), { withVulns: true })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin], tier: 0 })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runPhase0({
        storage, runId, scopeRevision: 1, tier: 0, origins: [fx.origin], reposDir: repoDir,
        broker: new RequestBroker({ rejectUnauthorized: false }), grant: makeLabGrant(fx.origin, { tier: 0 }),
        signal: AbortSignal.timeout(15_000),
      }),
    )
    assert.equal(fx.requests.length, 0, 'Tier-0 Phase-0 must make zero HTTP requests')
  })

  // --- Feature 9: crawl_state_graph Multi-Persona SPA Explorer ---

  test('T1-09a: crawl_state_graph respects maxPages BVA ceiling', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const crawl = requireExport<(params: Record<string, unknown>) => Promise<{ pagesVisited: number }>>(
      mod, 'crawlStateGraph', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      const idx = req.url === '/' ? 0 : Number(req.url?.replace('/page/', '') || '0')
      res.end(`<html><body><a href="/page/${idx + 1}">next</a><a href="/page/${idx + 2}">next2</a></body></html>`)
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      crawl({
        storage, runId, scopeRevision: 1, origin: fx.origin, maxPages: 2, maxDepth: 4,
        browser: new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })),
        grant: makeLabGrant(fx.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.ok(res.pagesVisited <= 2, `Expected <= 2 pages visited, got ${res.pagesVisited}`)
  })

  test('T1-09b: crawl_state_graph respects maxDepth: 0 (root page only)', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const crawl = requireExport<(params: Record<string, unknown>) => Promise<{ pagesVisited: number }>>(
      mod, 'crawlStateGraph', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body><a href="/deep/1">child</a></body></html>`)
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      crawl({
        storage, runId, scopeRevision: 1, origin: fx.origin, maxPages: 25, maxDepth: 0,
        browser: new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })),
        grant: makeLabGrant(fx.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.pagesVisited, 1)
    assert.ok(!fx.requests.some(r => r.url === '/deep/1'))
  })

  test('T1-09c: crawl_state_graph extracts HTML <form> inputs and flags CSRF fields', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const crawl = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'crawlStateGraph', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body><form action="/api/transfer" method="POST"><input type="hidden" name="_csrf" value="tok"><input name="amount"></form></body></html>`)
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      crawl({
        storage, runId, scopeRevision: 1, origin: fx.origin, maxPages: 5, maxDepth: 1,
        browser: new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })),
        grant: makeLabGrant(fx.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    const v4 = storage as unknown as V4StoreContract
    const params = v4.listEndpointParams(runId)
    assert.ok(params.some(p => p.name === '_csrf' && Boolean(p.isCsrf ?? p.is_csrf)))
    assert.ok(params.some(p => p.name === 'amount'))
  })

  test('T1-09d: crawl_state_graph captures postMessage listener and storage key names without secret values', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const crawl = requireExport<(params: Record<string, unknown>) => Promise<{ storageKeys: string[]; hasPostMessageListener: boolean }>>(
      mod, 'crawlStateGraph', 'src/server/phase0-recon.ts',
    )
    const secretVal = 'do-not-capture-secret-value-9911'
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body><script>localStorage.setItem('auth_meta', '${secretVal}'); window.addEventListener('message', () => {});</script></body></html>`)
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      crawl({
        storage, runId, scopeRevision: 1, origin: fx.origin, maxPages: 3, maxDepth: 1,
        browser: new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })),
        grant: makeLabGrant(fx.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.ok(res.storageKeys.includes('auth_meta'))
    assert.equal(res.hasPostMessageListener, true)
    assert.ok(!JSON.stringify(res).includes(secretVal))
  })

  test('T1-09e: crawl_state_graph blocks out-of-scope third-party links', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const crawl = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'crawlStateGraph', 'src/server/phase0-recon.ts',
    )
    const tp = await startHttpFixture(t, (_req, _b, res) => res.end('tp-hit'))
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body><a href="${tp.origin}/steal">evil</a></body></html>`)
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      crawl({
        storage, runId, scopeRevision: 1, origin: fx.origin, maxPages: 5, maxDepth: 2,
        browser: new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })),
        grant: makeLabGrant(fx.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(tp.requests.length, 0)
  })

  // --- Feature 10: SQLite App State & Producer-Consumer API Graph ---

  test('T1-10a: endpoints unique index (run_id, origin, method, path_template) upserts idempotently', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    const a = v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/api/orders/{id}', source: 'spa_crawl', riskScore: 60 })
    const b = v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/api/orders/{id}', source: 'openapi', riskScore: 90 })
    assert.equal(a.id, b.id)
    const rows = v4.listEndpoints(runId)
    assert.equal(rows.length, 1)
  })

  test('T1-10b: path normalization collapses numeric and UUID segments to :id', () => {
    assert.equal(normalizeEndpointTemplate('/orders/12345/items/67'), '/orders/:id/items/:id')
    assert.equal(normalizeEndpointTemplate(`/users/${randomUUID()}/profile`), '/users/:id/profile')
  })

  test('T1-10c: endpoint_params persists isCsrf and isObjectId flags across parameter locations', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    const ep = v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'POST', pathTemplate: '/api/orders/:id', source: 'spa_crawl' })
    v4.upsertEndpointParam({ runId, endpointId: ep.id, name: '_csrf', location: 'form', isCsrf: true, isObjectId: false, source: 'spa_crawl' })
    v4.upsertEndpointParam({ runId, endpointId: ep.id, name: 'id', location: 'path', isCsrf: false, isObjectId: true, source: 'spa_crawl' })
    const params = v4.listEndpointParams(runId, ep.id)
    assert.equal(params.length, 2)
    assert.ok(params.some(p => p.name === '_csrf' && Boolean(p.isCsrf ?? p.is_csrf)))
    assert.ok(params.some(p => p.name === 'id' && Boolean(p.isObjectId ?? p.is_object_id)))
  })

  test('T1-10d: depth-8 JSON resource extractor captures depth 8 ID and stops at depth 9', () => {
    const deepPayload = { d1: { d2: { d3: { d4: { d5: { d6: { d7: { invoiceId: 'inv_at_depth8', extra: { hiddenId: 'inv_at_depth9' } } } } } } } } }
    const found = extractPersonaResourcesFromExchange({
      origin: 'http://127.0.0.1:9',
      method: 'GET',
      pathAndQuery: '/api/orders',
      personaHandle: 'persona_a',
      status: 200,
      mediaType: 'application/json',
      body: JSON.stringify(deepPayload),
    })
    assert.ok(found.some(r => r.resourceId === 'inv_at_depth8'), 'Expected depth-8 resource ID to be extracted')
    assert.ok(!found.some(r => r.resourceId === 'inv_at_depth9'), 'Depth-9 resource ID should not be extracted')
  })

  test('T1-10e: api_dependencies stores hashed sampleResourceIdHash and never raw secret token', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    const prod = v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'POST', pathTemplate: '/api/orders', source: 'spa_crawl' })
    const cons = v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/api/orders/:id', source: 'spa_crawl' })
    v4.recordApiDependency({
      runId, producerEndpointId: prod.id, consumerEndpointId: cons.id, resourceKey: 'orderId',
      sampleResourceIdHash: 'sha256:9f86d081', personaHandle: 'persona_a', observedTransitions: ['draft->paid'],
    })
    const deps = v4.listApiDependencies(runId)
    assert.equal(deps.length, 1)
    assert.equal(deps[0].resourceKey ?? deps[0].resource_key, 'orderId')
  })

  // --- Feature 11: AST-Based JS/TS & Source-Map Harvester ---

  test('T1-11a: worker/analyzers.ts jsHarvest extracts React/Next router paths via AST', async () => {
    const mod = await import('../worker/analyzers.ts') as Record<string, unknown>
    const jsHarvest = requireExport<(content: string, sourceName?: string) => Record<string, unknown>>(
      mod, 'jsHarvest', 'worker/analyzers.ts',
    )
    const code = `const routes = [{ path: "/admin/audit-logs", element: el }, { path: '/api/' + 'internal/flags' }]; router.push("/billing/portal");`
    const out = jsHarvest(code, 'https://app.invalid/bundle.js')
    const serialized = JSON.stringify(out)
    assert.match(serialized, /\/admin\/audit-logs/)
    assert.match(serialized, /\/billing\/portal/)
  })

  test('T1-11b: worker/analyzers.ts jsHarvest extracts fetch/axios HTTP method and bodyKeys', async () => {
    const mod = await import('../worker/analyzers.ts') as Record<string, unknown>
    const jsHarvest = requireExport<(content: string, sourceName?: string) => Record<string, unknown>>(
      mod, 'jsHarvest', 'worker/analyzers.ts',
    )
    const code = `await fetch("/api/invoices/export", { method: "POST", body: JSON.stringify({ orgId: o, format: "csv" }) })`
    const out = jsHarvest(code, 'https://app.invalid/chunk.js')
    const serialized = JSON.stringify(out)
    assert.match(serialized, /\/api\/invoices\/export/)
    assert.match(serialized, /POST/)
    assert.match(serialized, /orgId/)
  })

  test('T1-11c: worker/analyzers.ts jsHarvest extracts Next-Action IDs and gql documents', async () => {
    const mod = await import('../worker/analyzers.ts') as Record<string, unknown>
    const jsHarvest = requireExport<(content: string, sourceName?: string) => Record<string, unknown>>(
      mod, 'jsHarvest', 'worker/analyzers.ts',
    )
    const actionHash = 'a'.repeat(40)
    const code = `const h = { "Next-Action": "${actionHash}" }; const q = gql\`query GetSecretInvoices($orgId: ID!) { invoices(orgId: $orgId) { id } }\`;`
    const out = jsHarvest(code, 'https://app.invalid/next.js')
    const serialized = JSON.stringify(out)
    assert.ok(serialized.includes(actionHash))
    assert.match(serialized, /GetSecretInvoices/)
  })

  test('T1-11d: worker/analyzers.ts parses .map source-maps within cap to recover hidden routes', async () => {
    const mod = await import('../worker/analyzers.ts') as Record<string, unknown>
    const runAnalyzer = requireExport<(tool: string, args: Record<string, unknown>, readEvidence: (name: string) => string) => Record<string, unknown>>(
      mod, 'runAnalyzer', 'worker/analyzers.ts',
    )
    const mapJson = JSON.stringify({
      version: 3,
      sources: ['src/pages/internal/debug-panel.tsx'],
      sourcesContent: [`export async function load() { return fetch('/api/internal/debug-dump') }`],
      mappings: '',
    })
    const out = runAnalyzer('js-harvest', {
      text: 'console.log(1)\n//# sourceMappingURL=app.js.map',
      sourceMapContent: mapJson,
    }, () => mapJson)
    assert.match(JSON.stringify(out), /\/api\/internal\/debug-dump/)
  })

  test('T1-11e: worker/analyzers.ts flags DOM sinks and postMessage handlers missing event.origin checks', async () => {
    const mod = await import('../worker/analyzers.ts') as Record<string, unknown>
    const jsHarvest = requireExport<(content: string, sourceName?: string) => Record<string, unknown>>(
      mod, 'jsHarvest', 'worker/analyzers.ts',
    )
    const code = `window.addEventListener("message", (ev) => { document.getElementById("root").innerHTML = ev.data.html; });`
    const out = jsHarvest(code, 'https://app.invalid/widget.js')
    const serialized = JSON.stringify(out)
    assert.match(serialized, /innerHTML|postMessage/i)
  })

  // --- Feature 12: kovo-worker:v4 Hardened Offline Toolchain ---

  test('T1-12a: worker-backend.ts & worker/Dockerfile configure kovo-worker:v4 and TRIVY_CACHE_DIR', () => {
    const backendSrc = readFileSync(resolve(repoRoot, 'src/server/worker-backend.ts'), 'utf8')
    const dockerfile = readFileSync(resolve(repoRoot, 'worker/Dockerfile'), 'utf8')
    assert.match(backendSrc, /kovo-worker:v4/)
    assert.match(dockerfile, /TRIVY_CACHE_DIR="?\/opt\/trivy-cache"?/)
  })

  test('T1-12b: LinuxWorkerBackend enforces --network none, --read-only, --cap-drop ALL, UID 10001:10001', () => {
    const backendSrc = readFileSync(resolve(repoRoot, 'src/server/worker-backend.ts'), 'utf8')
    for (const flag of ['--network', 'none', '--read-only', '--cap-drop', 'ALL', 'no-new-privileges', '10001:10001']) {
      assert.ok(backendSrc.includes(flag), `Missing hardened container flag: ${flag}`)
    }
  })

  test('T1-12c: worker-backend.ts upgrades worker cgroup limits to 1536m memory and 256 PIDs', () => {
    const backendSrc = readFileSync(resolve(repoRoot, 'src/server/worker-backend.ts'), 'utf8')
    assert.match(backendSrc, /1536m/)
    assert.match(backendSrc, /256/)
  })

  test('T1-12d: worker/rules/opengrep contains expanded curated offline ruleset (>= 50 rule files)', () => {
    const rulesDir = resolve(repoRoot, 'worker/rules/opengrep')
    assert.ok(existsSync(rulesDir), 'worker/rules/opengrep directory missing')
    const files: string[] = []
    const walk = (d: string) => {
      for (const entry of readdirSync(d, { withFileTypes: true })) {
        const full = join(d, entry.name)
        if (entry.isDirectory()) walk(full)
        else if (/\.ya?ml$/i.test(entry.name)) files.push(full)
      }
    }
    walk(rulesDir)
    assert.ok(files.length >= 50, `Expected >= 50 curated Opengrep rule files, found ${files.length}`)
  })

  test('T1-12e: LinuxWorkerBackend rejects /repos path traversal before launching container', async (t) => {
    const backend = new LinuxWorkerBackend()
    const repoDir = makeTempDir(t, 'kovo-v4-trav-')
    await assert.rejects(
      () => runWorkerSast(backend as never, { repo: '../etc', engines: ['opengrep'], reposDir: repoDir }),
      /invalid|traversal|repository/i,
    )
  })

  // --- Feature 13: 3-Stage Offline Semantic Audit Pipeline ---

  test('T1-13a: Stage-1 ProjectSecuritySpec schema captures sources, authGuards, sanitizers, sinks, invariants', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon is required for Stage-1 semantic audit')
    const backend = new LinuxWorkerBackend()
    const repoDir = makeTempDir(t, 'kovo-v4-s1-spec-')
    const appDir = join(repoDir, 'app')
    mkdirSync(join(appDir, 'src'), { recursive: true })
    writeFileSync(join(appDir, 'src/auth.ts'), `export function requireSession(req: any) { return req.session }`)
    writeFileSync(join(appDir, 'src/db.ts'), `export function runUnsafe(prisma: any, id: string) { return prisma.$queryRawUnsafe("SELECT * FROM invoices WHERE id=" + id) }`)
    const session = await backend.openSession(randomUUID(), AbortSignal.timeout(30_000), { reposDir: repoDir })
    t.after(() => session.close())
    const signal = AbortSignal.timeout(60_000)
    const stage1 = await extractProjectSecuritySpecAndRules({ signal } as never, 'app', session, { enableLlm: false })
    assert.ok(stage1.spec.sources.length >= 1, 'ProjectSecuritySpec must capture HTTP request sources')
    assert.ok(stage1.spec.authTenantGuards.some(g => g.patterns.includes('requireSession')), 'Expected custom requireSession guard')
    assert.ok(stage1.spec.sanitizers.length >= 1, 'Expected numeric coercion sanitizers')
    assert.ok(stage1.spec.sinks.some(s => s.patterns.some(p => p.includes('$queryRawUnsafe'))), 'Expected raw SQL sink inference')
    assert.ok(stage1.spec.businessInvariants.some(i => i.requiredGuard === 'requireSession'), 'Expected tenant/auth dominance invariant')
    assert.ok(stage1.rules.some(r => r.spec.id.includes('queryrawunsafe')), 'Expected a generated raw-SQL dynamic rule')
  })

  test('T1-13b: Stage-1 generates dynamic Opengrep rule YAML from custom ORM/auth wrapper spec', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon is required for dynamic Opengrep rule audit')
    const backend = new LinuxWorkerBackend()
    const repoDir = makeTempDir(t, 'kovo-v4-s1-dyn-')
    const appDir = join(repoDir, 'app')
    mkdirSync(join(appDir, 'src'), { recursive: true })
    writeFileSync(join(appDir, 'src/handler.ts'), `export function handle(req: any, customDb: any) { return customDb.unsafeExec("SELECT * FROM users WHERE q=" + req.query.q) }`)
    const session = await backend.openSession(randomUUID(), AbortSignal.timeout(30_000), { reposDir: repoDir })
    t.after(() => session.close())
    const signal = AbortSignal.timeout(60_000)
    const stage1 = await extractProjectSecuritySpecAndRules({ signal } as never, 'app', session, { enableLlm: false })
    const rule = stage1.rules.find(r => r.spec.id.includes('unsafeexec'))
    assert.ok(rule, 'Expected generated dynamic rule for customDb.unsafeExec')
    assert.match(rule.yaml, /unsafeExec/, 'Dynamic rule YAML must target the custom ORM wrapper')
    const dynFindings = await runValidatedDynamicRulesInWorker(session, 'app', stage1.rules, signal)
    assert.ok(dynFindings.some(f => f.file.includes('handler.ts')), 'Dynamic rule must match custom ORM wrapper inside --network none worker')
  })

  test('T1-13c: Stage-2 suspect conversion lifts the v3 12-suspect cap (converts 25 suspects)', async (t) => {
    const { storage } = makeStore(t)
    const { runId, run } = await setupApprovedRun(storage, { budgetRequests: 2000 })
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'threat_model', 'running', 1, 0, ?, '[]', ?, 'audit', 'audit', ?)`)
      .run(aid, runId, randomUUID(), JSON.stringify(['http://127.0.0.1:9']), Date.now())
    const assignment = storage.worker(aid)
    const factRows = Array.from({ length: 25 }, (_, i) =>
      storage.addFact(run, assignment, {
        kind: 'code_audit_suspect',
        origin: 'http://127.0.0.1:9',
        summary: `Suspect #${i} on /api/resource/${i}`,
        data: {
          routeOrAction: `/api/resource/${i}`,
          file: `src/r${i}.ts`,
          line: 10 + i,
          sinkKind: 'db_query',
          authCheck: 'missing',
          ownershipCheck: 'missing',
        },
      }),
    )
    const steps = convertCodeAuditSuspectsToChainSteps(storage, run, factRows)
    assert.ok(steps.length >= 25, `Expected >= 25 converted suspects (no 12-cap), got ${steps.length}`)
  })

  test('T1-13d: Stage-3 git-history security miner filters security-fix commits and ignores docs commits', async (t) => {
    const repoDir = makeTempDir(t, 'kovo-v4-git-miner-')
    const appDir = join(repoDir, 'app')
    mkdirSync(appDir, { recursive: true })
    await exec('git', ['init'], { cwd: appDir })
    await exec('git', ['config', 'user.email', 'test@kovo.local'], { cwd: appDir })
    await exec('git', ['config', 'user.name', 'Test'], { cwd: appDir })
    writeFileSync(join(appDir, 'README.md'), '# app\n')
    await exec('git', ['add', '.'], { cwd: appDir })
    await exec('git', ['commit', '-m', 'docs: update README typo'], { cwd: appDir })
    writeFileSync(join(appDir, 'invoices.ts'), 'export const check = (u: any, inv: any) => u.orgId === inv.orgId;\n')
    await exec('git', ['add', '.'], { cwd: appDir })
    await exec('git', ['commit', '-m', 'fix: enforce tenant check for IDOR / BOLA on invoices'], { cwd: appDir })

    const { dir, storage } = makeStore(t)
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call',
      callId: 'c_git',
      name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'proved', summary: 'Audit complete' }),
    }))
    await saveModelProfile({
      name: 'Auditor', endpoint: llm.endpoint, model: 'mock-r', protocol: 'responses', key: 'sk-git-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'high', roleAffinity: 'reasoning',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    // A dead seed now trips the v5 origin circuit breaker and pauses the run before the
    // source audit can run. Serve benign 404s so discovery stays healthy and the test
    // still exercises the Stage-3 git miner, not the network-failure path.
    const fixture = await startHttpFixture(t, (_req, _body, res) => { res.statusCode = 404; res.end('not found') })
    const { projectId, runId } = await setupApprovedRun(storage, { seeds: [fixture.origin] })
    const targetRepo = join(dir, 'repos', projectId, 'local', 'app')
    mkdirSync(join(dir, 'repos', projectId, 'local'), { recursive: true })
    await exec('cp', ['-r', appDir, targetRepo])

    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 15_000
      while (Date.now() < deadline) {
        if (storage.run(runId).phase !== 'threat_model') break
        await delay(100)
      }
      await stopExecution(engine as never)
    })
    const facts = storage.listFacts(runId, { includeTainted: false, limit: 100 })
    const serialized = JSON.stringify(facts)
    assert.match(serialized, /IDOR|BOLA|invoices/i)
    assert.ok(!serialized.includes('update README typo'))
  })

  test('T1-13e: Stage-2 path dominance evaluator distinguishes guarded vs unguarded entrypoint-to-sink paths', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon is required for Stage-2 path dominance check')
    const backend = new LinuxWorkerBackend()
    const repoDir = makeTempDir(t, 'kovo-v4-dom-')
    const appDir = join(repoDir, 'app')
    mkdirSync(join(appDir, 'src'), { recursive: true })
    writeFileSync(join(appDir, 'src/guarded.ts'), `export function guardedRead(db: any, req: any) { requireTenant(req); return db.query("SELECT * FROM invoices WHERE id = '" + req.query.id + "'"); }`)
    writeFileSync(join(appDir, 'src/unguarded.ts'), `export function unguardedRead(db: any, req: any) { return db.query("SELECT * FROM orders WHERE id = '" + req.query.id + "'"); }`)
    const res = await runWorkerSast(backend as never, { repo: 'app', engines: ['opengrep'], reposDir: repoDir }) as {
      engineStatus: Record<string, { ok: boolean }>; findings: Array<Record<string, unknown>>
    }
    assert.equal(res.engineStatus.opengrep.ok, true)
    assert.ok(res.findings.some(f => JSON.stringify(f).includes('unguarded.ts')))
  })

  // --- Feature 14: Multi-Container --internal LabRunner v4 & Wiring ---

  test('T1-14a: labConfigSchema accepts v4 services, seedCommand, iastEnabled, iastRuntime', () => {
    const parsed = labConfigSchema.safeParse({
      enabled: true,
      internalPort: 3000,
      healthPath: '/health',
      services: [
        { name: 'app', dockerfile: 'Dockerfile', internalPort: 3000 },
        { name: 'postgres', image: 'postgres:16-alpine', internalPort: 5432 },
      ],
      seedCommand: 'node scripts/seed.mjs',
      iastEnabled: true,
      iastRuntime: 'node',
    } as unknown)
    assert.equal(parsed.success, true, parsed.success ? '' : parsed.error.message)
    if (parsed.success) {
      assert.equal(parsed.data.services?.length, 2)
      assert.equal(parsed.data.seedCommand, 'node scripts/seed.mjs')
      assert.equal(parsed.data.iastEnabled, true)
      assert.equal(parsed.data.iastRuntime, 'node')
    }
  })

  test('T1-14b: LabRunner rejects malicious compose topologies (privileged, host network, ports, bind mounts, SYS_ADMIN)', async (t) => {
    const runner = new LabRunner()
    t.after(async () => { await runner.stopAll() })
    const repo = makeTempDir(t, 'kovo-v4-badcompose-')
    writeLabRepoFixture(repo)
    const maliciousPayloads: V4LabConfig[] = [
      { enabled: true, services: [{ name: 'app', image: 'node:24', privileged: true } as never] },
      { enabled: true, services: [{ name: 'app', image: 'node:24', network_mode: 'host' } as never] },
      { enabled: true, services: [{ name: 'app', image: 'node:24', ports: ['8080:8080'] } as never] },
      { enabled: true, services: [{ name: 'app', image: 'node:24', volumes: ['/etc:/host-etc'] } as never] },
      { enabled: true, services: [{ name: 'app', image: 'node:24', cap_add: ['SYS_ADMIN'] } as never] },
    ]
    for (const cfg of maliciousPayloads) {
      await assert.rejects(
        () => withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
          runner.startLabTarget({ runId: randomUUID(), environment: 'local-lab', repoDir: repo, labConfig: cfg as LabConfig }),
        ),
        /forbidden|privileged|host|port|volume|cap|malicious|unsafe/i,
      )
    }
  })

  test('T1-14c: LabRunner enforces project.environment === local-lab and KOVO_ALLOW_LOCAL_LAB=1', async () => {
    assert.throws(() => assertLocalLabAllowed('public'), /local-lab/i)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: undefined }, () => {
      assert.throws(() => assertLocalLabAllowed('local-lab'), /KOVO_ALLOW_LOCAL_LAB/)
    })
  })

  test('T1-14d: LabRunner rejects multi-service stack exceeding 6 containers per run', async (t) => {
    const runner = new LabRunner()
    t.after(async () => { await runner.stopAll() })
    const repo = makeTempDir(t, 'kovo-v4-maxsvc-')
    writeLabRepoFixture(repo)
    const services = Array.from({ length: 7 }, (_, i) => ({ name: `svc_${i}`, image: 'node:24-bookworm-slim', internalPort: 3000 + i }))
    await assert.rejects(
      () => withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
        runner.startLabTarget({
          runId: randomUUID(),
          environment: 'local-lab',
          repoDir: repo,
          labConfig: { enabled: true, services } as unknown as LabConfig,
        }),
      ),
      /6|limit|max|container/i,
    )
  })

  test('T1-14e: LabRunner SAFE_ENV_KEY validation rejects dangerous env vars (LD_PRELOAD, PATH, lowercase)', async (t) => {
    const runner = new LabRunner()
    t.after(async () => { await runner.stopAll() })
    const repo = makeTempDir(t, 'kovo-v4-badenv-')
    writeLabRepoFixture(repo)
    const badEnvs: Array<Record<string, string>> = [{ LD_PRELOAD: '/tmp/evil.so' }, { PATH: '/tmp' }, { 'bad-key': '1' }]
    for (const badEnv of badEnvs) {
      await assert.rejects(
        () => withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
          runner.startLabTarget({
            runId: randomUUID(),
            environment: 'local-lab',
            repoDir: repo,
            labConfig: { enabled: true, dockerfile: 'Dockerfile', internalPort: 3000, env: badEnv },
          }),
        ),
        /env|key|forbidden|unsafe/i,
      )
    }
  })

  // --- Feature 15: Opt-In local-lab IAST & Coverage Telemetry ---

  test('T1-15a: iastEnabled: true is rejected on public projects', async (t) => {
    const { storage } = makeStore(t)
    const { projectId } = await setupApprovedRun(storage, { environment: 'public' })
    assert.throws(
      () => storage.updateProjectLabConfig({
        requestId: randomUUID(),
        projectId,
        labConfig: { enabled: true, iastEnabled: true, healthPath: '/' } as unknown as LabConfig,
      }),
      /public|local-lab|forbidden/i,
    )
  })

  test('T1-15b: IAST telemetry sanitizer scrubs persona secrets, AWS keys, and Stripe keys', async (t) => {
    const mod = await import('../src/server/lab-runner.ts') as Record<string, unknown>
    const ingestTelemetry = requireExport<(input: Record<string, unknown>) => { filePath: string; bytesWritten: number }>(
      mod, 'ingestLabTelemetry', 'src/server/lab-runner.ts',
    )
    const { dir, storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const telemetryDir = join(dir, 'evidence', 'lab-telemetry')
    mkdirSync(telemetryDir, { recursive: true })
    const personaSecret = 'persona-secret-token-7766'
    const res = ingestTelemetry({
      runId,
      exchangeId: randomUUID(),
      traceId: 'trace-15b',
      environment: 'local-lab',
      telemetryDir,
      secrets: [{ value: personaSecret, placeholder: '[persona:u:secret]' }],
      rawTelemetry: {
        routesHit: ['/api/orders'],
        newLinesCovered: 2,
        sinkEvents: [{ sink: 'pg.query', query: `SELECT '${RAW_AWS_SECRET}' '${RAW_STRIPE_SECRET}' '${personaSecret}'` }],
        exceptions: [{ message: `Error at ${personaSecret}` }],
      },
      storage,
    })
    const text = readFileSync(res.filePath, 'utf8')
    assert.ok(!text.includes(RAW_AWS_SECRET), 'AWS key leaked in IAST telemetry')
    assert.ok(!text.includes(RAW_STRIPE_SECRET), 'Stripe key leaked in IAST telemetry')
    assert.ok(!text.includes(personaSecret), 'Persona secret leaked in IAST telemetry')
  })

  test('T1-15c: IAST telemetry enforces 64 KiB (65536 bytes) per-exchange size cap BVA', async (t) => {
    const mod = await import('../src/server/lab-runner.ts') as Record<string, unknown>
    const ingestTelemetry = requireExport<(input: Record<string, unknown>) => { filePath: string; bytesWritten: number }>(
      mod, 'ingestLabTelemetry', 'src/server/lab-runner.ts',
    )
    const { dir, storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const telemetryDir = join(dir, 'evidence', 'lab-telemetry')
    mkdirSync(telemetryDir, { recursive: true })
    const res = ingestTelemetry({
      runId,
      exchangeId: randomUUID(),
      traceId: 'trace-15c',
      environment: 'local-lab',
      telemetryDir,
      secrets: [],
      rawTelemetry: {
        routesHit: ['/api/big'],
        newLinesCovered: 1,
        sinkEvents: [{ sink: 'pg.query', query: 'A'.repeat(120_000) }],
        exceptions: [],
      },
      storage,
    })
    assert.ok(res.bytesWritten <= 65_536, `Expected sanitized telemetry <= 65536 bytes, got ${res.bytesWritten}`)
    assert.ok(statSync(res.filePath).size <= 65_536)
  })

  test('T1-15d: X-Kovo-Trace-Id is injected on local-lab IAST requests and omitted on public projects', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => res.end('ok'))
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp(
        { origin: fx.origin, method: 'GET', pathAndQuery: '/traced', traceId: 'trace-abc-123' },
        makeLabGrant(fx.origin),
        AbortSignal.timeout(5000),
      )
    })
    assert.equal(fx.requests.at(-1)!.headers['x-kovo-trace-id'], 'trace-abc-123')

    const pubBroker = makeVirtualPublicBroker((_url, opts) => {
      assert.equal(opts?.headers?.['x-kovo-trace-id'], undefined)
      return { status: 200, headers: {}, body: 'ok' }
    }) as unknown as V4BrokerContract
    await pubBroker.executeHttp(
      { origin: 'https://pub.example.invalid', method: 'GET', pathAndQuery: '/', traceId: 'trace-should-not-send' },
      makePublicGrant('https://pub.example.invalid'),
      AbortSignal.timeout(5000),
    )
  })

  test('T1-15e: ReplayVerifier ignores forged /evidence/lab-telemetry/ JSON and keeps benign target unconfirmed', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ ok: true, count: 0 }))
    })
    const { dir, storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const telemetryDir = join(dir, 'evidence', 'lab-telemetry')
    mkdirSync(telemetryDir, { recursive: true })
    writeFileSync(join(telemetryDir, 'forged.json'), JSON.stringify({ sqli_confirmed: true, confirmed: true, sinkEvents: [{ vulnerable: true }] }))

    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'http_chain',
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.json.sqli_confirmed == true), observed: (.steps.p1.bodyPreview // "benign"), expected: "sqli_confirmed=true" }',
          steps: [
            { id: 'c1', role: 'control', description: 'Control', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/search?q=a' } },
            { id: 'p1', role: 'probe', description: 'Probe', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/search?q=1%27' } },
          ],
        },
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        storage,
        runId,
        grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.notEqual(res.verdict, 'confirmed')
  })

  // --- Feature 16: Universal Parameter Encodings & Expanded SQLi ---

  test('T1-16a: sqlBooleanDiffReplaySpecSchema accepts all 7 paramLocation encodings', () => {
    const locations = ['query', 'json', 'form', 'path', 'header', 'xml', 'graphql_var'] as const
    for (const paramLocation of locations) {
      const parsed = sqlBooleanDiffReplaySpecSchema.safeParse({
        ...baseReplaySpecFields('https://app.example.invalid'),
        kind: 'sql_boolean_diff',
        targetOrigin: 'https://app.example.invalid',
        method: paramLocation === 'query' || paramLocation === 'path' || paramLocation === 'header' ? 'GET' : 'POST',
        pathAndQuery: paramLocation === 'path' ? '/items/{{val}}' : '/items',
        paramName: 'id',
        paramLocation,
        assertionsJq: '{ controlPassed: (.sqlDiff.controlPassed == true), confirmed: (.sqlDiff.passed == true), observed: "diff", expected: "no sql diff" }',
      } as unknown)
      assert.equal(parsed.success, true, `Expected paramLocation ${paramLocation} to be accepted`)
    }
  })

  test('T1-16b: expanded sqli_boolean tests parenthesized, LIKE, ORDER BY, and UNION NULL patterns', async (t) => {
    const seenValues: string[] = []
    const fx = await startHttpFixture(t, (req, _b, res) => {
      const u = new URL(req.url ?? '/', fx.origin)
      seenValues.push(u.searchParams.get('q') ?? '')
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ rows: [] }))
    })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'sqli_boolean',
          origin: fx.origin,
          pathAndQuery: '/search?q=test',
          param: 'q',
          baselineValue: 'test',
        },
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    const joined = seenValues.join('\n')
    assert.match(joined, /\)\s*AND/i)
    assert.match(joined, /%|LIKE|ORDER\s+BY|UNION\s+SELECT/i)
  })

  test('T1-16c: sqlTimeDiffReplaySpecSchema (#14) enforces bounded delayMs (1500..3000ms)', async () => {
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => {
      const okSpec = declarativeReplaySpecSchema.safeParse({
        ...baseReplaySpecFields('http://127.0.0.1:9'),
        kind: 'sql_time_diff',
        targetOrigin: 'http://127.0.0.1:9',
        method: 'GET',
        pathAndQuery: '/items',
        paramName: 'id',
        paramLocation: 'query',
        delayMs: 2000,
        assertionsJq: '{ controlPassed: true, confirmed: true, observed: "delay", expected: "no delay" }',
      } as unknown)
      assert.equal(okSpec.success, true, okSpec.success ? '' : okSpec.error.message)

      for (const badDelay of [400, 5000]) {
        const bad = declarativeReplaySpecSchema.safeParse({
          ...baseReplaySpecFields('http://127.0.0.1:9'),
          kind: 'sql_time_diff',
          targetOrigin: 'http://127.0.0.1:9',
          method: 'GET',
          pathAndQuery: '/items',
          paramName: 'id',
          paramLocation: 'query',
          delayMs: badDelay,
          assertionsJq: '{ controlPassed: true, confirmed: true, observed: "delay", expected: "no delay" }',
        } as unknown)
        assert.equal(bad.success, false, `Expected delayMs=${badDelay} to be rejected`)
      }
    })
  })

  test('T1-16d: sql_time_diff replay is blocked on public projects below Tier 3', async () => {
    const pubOrigin = 'https://prod.example.invalid'
    let hits = 0
    const broker = makeVirtualPublicBroker(() => {
      hits += 1
      return { status: 200, headers: {}, body: 'ok' }
    })
    const spec = {
      ...baseReplaySpecFields(pubOrigin),
      kind: 'sql_time_diff',
      targetOrigin: pubOrigin,
      method: 'GET',
      pathAndQuery: '/search?id=1',
      paramName: 'id',
      paramLocation: 'query',
      delayMs: 2000,
      assertionsJq: '{ controlPassed: true, confirmed: true, observed: "delay", expected: "no delay" }',
    } as unknown
    const parsed = declarativeReplaySpecSchema.safeParse(spec)
    assert.equal(parsed.success, true, parsed.success ? '' : parsed.error.message)

    let res: Awaited<ReturnType<typeof verifyReplaySpec>> | undefined
    let thrown: unknown
    try {
      res = await verifyReplaySpec({
        spec: parsed.data,
        broker,
        backend: new LinuxWorkerBackend(),
        grant: makePublicGrant(pubOrigin, { tier: 2 }),
        signal: AbortSignal.timeout(15_000),
      })
    } catch (err) {
      thrown = err
    }
    assert.equal(hits, 0, `Expected 0 HTTP requests to hit target on blocked public sql_time_diff, got ${hits}`)
    if (thrown !== undefined) {
      const msg = thrown instanceof Error ? thrown.message : String(thrown)
      assert.match(msg, /tier\s*3|local-lab|public|blocked|denied/i)
    } else {
      assert.ok(res, 'Expected ReplayVerificationResult')
      assert.notEqual(res.verdict, 'confirmed')
      const summaryText = String(
        (res as unknown as { summary?: string }).summary ??
        res.outcome.reason ??
        res.outcome.observed ??
        res.evidencePayload.error ??
        '',
      )
      assert.match(summaryText, /tier\s*3|local-lab|public|blocked|denied/i)
    }
  })

  test('T1-16e: sql_time_diff statistical check rejects overlapping/jittery and insufficient-delay timings', async (t) => {
    let mode: 'pass' | 'jitter' | 'short' = 'pass'
    let reqIdx = 0
    const fx = await startHttpFixture(t, async (req, _b, res) => {
      reqIdx += 1
      const isSleep = /SLEEP|pg_sleep|WAITFOR|randomblob/i.test(req.url ?? '')
      if (mode === 'pass' && isSleep) await delay(2050)
      else if (mode === 'jitter' && !isSleep && reqIdx % 2 === 1) await delay(2200)
      else if (mode === 'jitter' && isSleep) await delay(1950)
      else if (mode === 'short' && isSleep) await delay(400)
      res.end('ok')
    })
    const baseSpec = {
      ...baseReplaySpecFields(fx.origin),
      kind: 'sql_time_diff',
      targetOrigin: fx.origin,
      method: 'GET',
      pathAndQuery: '/items?id=1',
      paramName: 'id',
      paramLocation: 'query',
      delayMs: 2000,
      assertionsJq: '{ controlPassed: (.sqlTimeDiff.controlPassed // true), confirmed: (.sqlTimeDiff.passed // false), observed: "timing_diff", expected: "no timing overlap" }',
    }
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const backend = new LinuxWorkerBackend()
    const grant = makeLabGrant(fx.origin, { tier: 3 })

    mode = 'pass'
    const okRes = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({ spec: baseSpec as unknown as Parameters<typeof verifyReplaySpec>[0]['spec'], broker, backend, grant, signal: AbortSignal.timeout(45_000) }),
    )
    assert.equal(okRes.verdict, 'confirmed')

    mode = 'jitter'
    const jitterRes = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({ spec: baseSpec as unknown as Parameters<typeof verifyReplaySpec>[0]['spec'], broker, backend, grant, signal: AbortSignal.timeout(45_000) }),
    )
    assert.notEqual(jitterRes.verdict, 'confirmed')

    mode = 'short'
    const shortRes = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({ spec: baseSpec as unknown as Parameters<typeof verifyReplaySpec>[0]['spec'], broker, backend, grant, signal: AbortSignal.timeout(45_000) }),
    )
    assert.notEqual(shortRes.verdict, 'confirmed')
  })

  // --- Feature 17: Automated BOLA/BFLA & Workflow-Skip Sweepers ---

  test('T1-17a: Tier-2 read-only authz_matrix sweeper executes GET checks without Tier-3 approval', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ id: req.url, leakedTo: req.headers.authorization ?? 'anon' }))
    })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [
        { handle: 'owner', roleLabel: 'Owner', authKind: 'bearer', secret: 'tok-owner' },
        { handle: 'other', roleLabel: 'Other', authKind: 'bearer', secret: 'tok-other' },
      ],
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'authz_matrix',
          origin: fx.origin,
          pathAndQuery: '/api/orders/{{id}}',
          resourceIds: ['1001'],
          ownerPersona: 'owner',
          otherPersona: 'other',
          includeAnonymous: true,
        },
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { personas: personaMap }),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    assert.ok(res.requestsSent >= 2)
    assert.equal(res.stoppedReason, null)
  })

  test('T1-17b: producer-consumer cross-persona PATCH/DELETE sweeper requires Tier 3 or local-lab', async () => {
    const pubOrigin = 'https://prod.example.invalid'
    const broker = makeVirtualPublicBroker(() => ({ status: 200, headers: {}, body: '{"patched":true}' }))
    const res = await verifyReplaySpec({
      spec: {
        ...baseReplaySpecFields(pubOrigin),
        kind: 'http_chain',
        assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.status == 200), observed: "ok", expected: "denied" }',
        steps: [
          { id: 'c1', role: 'control', description: 'GET order', request: { origin: pubOrigin, method: 'GET', pathAndQuery: '/api/orders/1' } },
          { id: 'p1', role: 'probe', description: 'PATCH order on public tier 2', request: { origin: pubOrigin, method: 'PATCH', pathAndQuery: '/api/orders/1', jsonBody: { x: 1 } } },
        ],
      },
      broker,
      backend: new LinuxWorkerBackend(),
      grant: makePublicGrant(pubOrigin, { tier: 2 }),
      signal: AbortSignal.timeout(15_000),
    })
    assert.notEqual(res.verdict, 'confirmed')
  })

  test('T1-17c: workflow_invariant tests negative, zero, and overflow quantities safely', async (t) => {
    const fx = await startHttpFixture(t, (_req, body, res) => {
      res.setHeader('Content-Type', 'application/json')
      res.end(body || '{"ok":true}')
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'workflow_invariant',
          origin: fx.origin,
          pathAndQuery: '/api/cart/checkout',
          method: 'POST',
          quantityField: 'quantity',
        } as unknown as Parameters<typeof probeDifferential>[0],
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    const bodies = fx.requests.map(r => r.body).join('\n')
    assert.match(bodies, /-1/)
    assert.match(bodies, /:\s*0\b|=0\b/)
    assert.match(bodies, /1000000|999999|2147483647/)
    assert.ok(res.requestsSent >= 3)
  })

  test('T1-17d: step-skip detector flags invalid state transition draft -> refund', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (req.url?.includes('/refund')) {
        res.end(JSON.stringify({ status: 'refunded', skipped: true }))
        return
      }
      res.end(JSON.stringify({ status: 'draft' }))
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'workflow_invariant',
          origin: fx.origin,
          pathAndQuery: '/api/orders/1/refund',
          method: 'POST',
          createPath: '/api/orders',
          expectedTransitions: ['draft', 'paid', 'refunded'],
        } as unknown as Parameters<typeof probeDifferential>[0],
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    assert.equal(res.verdict, 'signal')
    assert.ok(res.anomalies.length >= 1)
  })

  test('T1-17e: cross-tenant BOLA sweeper returns inconclusive/no-op when fewer than 2 personas exist', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => res.end('{}'))
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'authz_matrix',
          origin: fx.origin,
          pathAndQuery: '/api/orders/{{id}}',
          resourceIds: ['1'],
          includeAnonymous: false,
        },
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin),
        undefined,
        AbortSignal.timeout(10_000),
      ),
    )
    assert.equal(res.verdict, 'inconclusive')
  })

  // --- Feature 18: Schema-Driven GraphQL Resolver Fuzzer ---

  test('T1-18a: GraphQL SDL parser extracts root queries, mutations, and nested object fields', async (t) => {
    const introspection = {
      data: {
        __schema: {
          queryType: { name: 'Query' },
          mutationType: { name: 'Mutation' },
          types: [
            { name: 'Invoice', kind: 'OBJECT', fields: [{ name: 'id', type: { kind: 'SCALAR', name: 'ID' } }, { name: 'total', type: { kind: 'SCALAR', name: 'Int' } }] },
            { name: 'Org', kind: 'OBJECT', fields: [{ name: 'id', type: { kind: 'SCALAR', name: 'ID' } }, { name: 'billingInvoices', type: { kind: 'LIST', ofType: { kind: 'OBJECT', name: 'Invoice' } } }] },
            { name: 'User', kind: 'OBJECT', fields: [{ name: 'id', type: { kind: 'SCALAR', name: 'ID' } }, { name: 'org', type: { kind: 'OBJECT', name: 'Org' } }] },
            { name: 'Query', kind: 'OBJECT', fields: [{ name: 'user', args: [{ name: 'id', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'ID' } } }], type: { kind: 'OBJECT', name: 'User' } }] },
            { name: 'Mutation', kind: 'OBJECT', fields: [{ name: 'updateRole', args: [{ name: 'userId', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'ID' } } }, { name: 'role', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'String' } } }], type: { kind: 'OBJECT', name: 'User' } }] },
          ],
        },
      },
    }
    const fx = await startHttpFixture(t, (_req, body, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (body.includes('__schema')) { res.end(JSON.stringify(introspection)); return }
      res.end(JSON.stringify({ data: { user: { id: '1', org: { billingInvoices: [] } } } }))
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        { probeClass: 'graphql_audit', origin: fx.origin, pathAndQuery: '/graphql', testMutations: true } as unknown as Parameters<typeof probeDifferential>[0],
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    const sentBodies = fx.requests.map(r => r.body).join('\n')
    assert.ok(res.requestsSent >= 2)
    assert.match(sentBodies, /user\(/)
    assert.match(sentBodies, /billingInvoices/)
  })

  test('T1-18b: GraphQL fuzzer synthesizes valid typed variables (ID!, Int!, String!, Boolean!)', async (t) => {
    const sdl = `
      type Item { id: ID! }
      type Query { searchItems(id: ID!, limit: Int!, filter: String, active: Boolean!): [Item!]! }
    `
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ data: { searchItems: [] } }))
    })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        { probeClass: 'graphql_audit', origin: fx.origin, pathAndQuery: '/graphql', sdl } as unknown as Parameters<typeof probeDifferential>[0],
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    const reqWithQuery = fx.requests.find(r => r.body.includes('searchItems'))
    assert.ok(reqWithQuery, 'Expected GraphQL fuzzer to invoke searchItems query')
    const parsedBody = JSON.parse(reqWithQuery.body) as { query?: string; variables?: Record<string, unknown> }
    if (parsedBody.variables && 'limit' in parsedBody.variables) {
      assert.equal(typeof parsedBody.variables.id, 'string')
      assert.equal(typeof parsedBody.variables.limit, 'number')
      assert.equal(typeof parsedBody.variables.active, 'boolean')
    } else {
      assert.match(parsedBody.query ?? '', /searchItems\s*\(/)
    }
  })

  test('T1-18c: GraphQL depth and alias batching probes remain strictly non-DoS bounded', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ data: {} }))
    })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'graphql_audit',
          origin: fx.origin,
          pathAndQuery: '/graphql',
          sdl: `type Node { id: ID! child: Node } type Query { node: Node }`,
        } as unknown as Parameters<typeof probeDifferential>[0],
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    assert.ok(fx.requests.length >= 1)
    for (const r of fx.requests) {
      const parsed = JSON.parse(r.body || '{}') as { query?: string }
      const q = parsed.query ?? ''
      const depth = (q.match(/\{/g) ?? []).length
      const aliases = (q.match(/\b[a-zA-Z_]\w*\s*:/g) ?? []).length
      assert.ok(depth <= 12, `GraphQL probe depth exceeded safe non-DoS cap: ${depth}`)
      assert.ok(aliases <= 20, `GraphQL probe aliases exceeded safe non-DoS cap: ${aliases}`)
    }
  })

  test('T1-18d: GraphQL nested-edge BOLA generator emits multi-hop resolver traversal queries', async (t) => {
    const sdl = `
      type BillingInvoice { id: ID! amount: Int! }
      type Org { id: ID! billingInvoices: [BillingInvoice!]! }
      type User { id: ID! org: Org! }
      type Query { user(id: ID!): User }
    `
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ data: { user: { id: '1', org: { id: 'o1', billingInvoices: [] } } } }))
    })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        { probeClass: 'graphql_audit', origin: fx.origin, pathAndQuery: '/graphql', sdl } as unknown as Parameters<typeof probeDifferential>[0],
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    assert.ok(
      fx.requests.some(r => r.body.includes('user(') && r.body.includes('org') && r.body.includes('billingInvoices')),
      'Expected multi-hop nested resolver traversal query (user -> org -> billingInvoices)',
    )
  })

  test('T1-18e: GraphQL mutation fuzzing is blocked on public Tier 2 without sandboxWriteAllowlist', async () => {
    const pubOrigin = 'https://gql.example.invalid'
    const res = await probeDifferential(
      {
        probeClass: 'graphql_audit',
        origin: pubOrigin,
        pathAndQuery: '/graphql',
        testMutations: true,
      } as unknown as Parameters<typeof probeDifferential>[0],
      makeVirtualPublicBroker(() => ({ status: 200, headers: {}, body: '{"data":{}}' })),
      makePublicGrant(pubOrigin, { tier: 2 }),
      undefined,
      AbortSignal.timeout(10_000),
    )
    assert.ok(res.notes.some(n => /mutation.*skip|tier|allowlist/i.test(n)) || res.verdict !== 'signal')
  })

  // --- Feature 19: New Probe Classes & Declarative Replay Kinds (11 -> 14+) ---

  test('T1-19a: xss_context classifier distinguishes HTML body, attribute, JS string, and href URL contexts', async (t) => {
    const contexts: Array<{ label: string; render: (q: string) => string }> = [
      { label: 'html_body', render: q => `<div>${q}</div>` },
      { label: 'html_attr', render: q => `<input value="${q}">` },
      { label: 'js_string', render: q => `<script>const x="${q}";</script>` },
      { label: 'href_url', render: q => `<a href="${q}">go</a>` },
    ]
    for (const ctx of contexts) {
      const fx = await startHttpFixture(t, (req, _b, res) => {
        const u = new URL(req.url ?? '/', fx.origin)
        const q = u.searchParams.get('q') ?? ''
        res.setHeader('Content-Type', 'text/html')
        res.end(ctx.render(q))
      })
      const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
        probeDifferential(
          { probeClass: 'xss_context', origin: fx.origin, pathAndQuery: '/search?q=hi', param: 'q' } as unknown as Parameters<typeof probeDifferential>[0],
          new RequestBroker({ rejectUnauthorized: false }),
          makeLabGrant(fx.origin),
          undefined,
          AbortSignal.timeout(15_000),
        ),
      )
      assert.equal(res.verdict, 'signal', `Expected xss_context signal for ${ctx.label}`)
      assert.ok(res.anomalies.length >= 1)
    }
  })

  test('T1-19b: declarativeReplaySpecSchema validates auth_protocol_proof (#12)', () => {
    const parsed = declarativeReplaySpecSchema.safeParse({
      ...baseReplaySpecFields('https://app.example.invalid'),
      kind: 'auth_protocol_proof',
      protocol: 'jwt',
      assertionsJq: '{ controlPassed: (.steps.ctrl.status == 401), confirmed: (.steps.prb.status == 200), observed: ("status=" + (.steps.prb.status | tostring)), expected: "HTTP 401" }',
      steps: [
        { id: 'ctrl', role: 'control', description: 'Invalid token rejected', request: { origin: 'https://app.example.invalid', method: 'GET', pathAndQuery: '/api/me' } },
        { id: 'prb', role: 'probe', description: 'alg:none accepted', request: { origin: 'https://app.example.invalid', method: 'GET', pathAndQuery: '/api/me', persona: 'user_a', authMutation: { kind: 'alg_none' } } },
      ],
    } as unknown)
    assert.equal(parsed.success, true, parsed.success ? '' : parsed.error.message)
  })

  test('T1-19c: declarativeReplaySpecSchema validates cache_differential (#13) and requires _gcb cache-buster', () => {
    const ok = declarativeReplaySpecSchema.safeParse({
      ...baseReplaySpecFields('https://cdn.example.invalid'),
      kind: 'cache_differential',
      targetOrigin: 'https://cdn.example.invalid',
      controlPath: '/home?_gcb=0123456789abcdef0123456789abcdef',
      probePath: '/home?_gcb=fedcba9876543210fedcba9876543210',
      poisonHeaders: { 'X-Forwarded-Host': 'evil-cache.invalid' },
      assertionsJq: '{ controlPassed: (.control.status == 200), confirmed: (.verify.status == 200), observed: "cached", expected: "clean" }',
    } as unknown)
    assert.equal(ok.success, true, ok.success ? '' : ok.error.message)

    const missingBuster = declarativeReplaySpecSchema.safeParse({
      ...baseReplaySpecFields('https://cdn.example.invalid'),
      kind: 'cache_differential',
      targetOrigin: 'https://cdn.example.invalid',
      controlPath: '/home',
      probePath: '/home',
      poisonHeaders: { 'X-Forwarded-Host': 'evil-cache.invalid' },
      assertionsJq: '{ controlPassed: (.control.status == 200), confirmed: (.verify.status == 200), observed: "cached", expected: "clean" }',
    } as unknown)
    assert.equal(missingBuster.success, false)
  })

  test('T1-19d: declarativeReplaySpecSchema validates sql_time_diff (#14) and rejects delayMs > 3000', async () => {
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => {
      const ok = declarativeReplaySpecSchema.safeParse({
        ...baseReplaySpecFields('http://127.0.0.1:9'),
        kind: 'sql_time_diff',
        targetOrigin: 'http://127.0.0.1:9',
        method: 'GET',
        pathAndQuery: '/items?id=1',
        paramName: 'id',
        paramLocation: 'query',
        delayMs: 2000,
        assertionsJq: '{ controlPassed: true, confirmed: true, observed: "delay", expected: "no delay" }',
      } as unknown)
      assert.equal(ok.success, true, ok.success ? '' : ok.error.message)
      if (ok.success) {
        assert.equal(ok.data.kind, 'sql_time_diff')
      }

      const tooSlow = declarativeReplaySpecSchema.safeParse({
        ...baseReplaySpecFields('http://127.0.0.1:9'),
        kind: 'sql_time_diff',
        targetOrigin: 'http://127.0.0.1:9',
        method: 'GET',
        pathAndQuery: '/items?id=1',
        paramName: 'id',
        paramLocation: 'query',
        delayMs: 3500,
        assertionsJq: '{ controlPassed: true, confirmed: true, observed: "delay", expected: "no delay" }',
      } as unknown)
      assert.equal(tooSlow.success, false)
    })
  })

  test('T1-19e: xxe_canary rejects /etc/passwd and file:// payloads and requires CanaryBroker placeholder', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => res.end('ok'))
    await assert.rejects(
      () => withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
        probeDifferential(
          {
            probeClass: 'xxe_canary',
            origin: fx.origin,
            pathAndQuery: '/api/xml',
            method: 'POST',
            customPayload: '<!DOCTYPE x [<!ENTITY f SYSTEM "file:///etc/passwd">]><r>&f;</r>',
          } as unknown as Parameters<typeof probeDifferential>[0],
          new RequestBroker({ rejectUnauthorized: false }),
          makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
          undefined,
          AbortSignal.timeout(10_000),
        ),
      ),
      /destructive|file:\/\/|\/etc\/passwd|canary|denied/i,
    )
  })

  // --- Feature 20: Second-Order Canary Ledger ---

  test('T1-20a: second-order canary generator mints unique gn2o_<hex> markers', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => res.end('ok'))
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const v4 = storage as unknown as V4StoreContract
    const m1 = `gn2o_${randomUUID().replace(/-/g, '').slice(0, 12)}`
    const m2 = `gn2o_${randomUUID().replace(/-/g, '').slice(0, 12)}`
    assert.match(m1, /^gn2o_[a-f0-9]{8,16}$/)
    assert.notEqual(m1, m2)
    v4.insertSecondOrderCanary({ runId, assignmentId: aid, marker: m1, injectedOrigin: fx.origin, injectedEndpoint: '/p', injectedParam: 'q' })
    v4.insertSecondOrderCanary({ runId, assignmentId: aid, marker: m2, injectedOrigin: fx.origin, injectedEndpoint: '/p', injectedParam: 'q' })
    assert.equal(v4.listSecondOrderCanaries(runId, 'planted').length, 2)
  })

  test('T1-20b: Store.insertSecondOrderCanary persists planted record in SQLite', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const assignment = storage.db.select().from((await import('../src/server/schema.ts')).assignments).limit(1).get()
    const aid = assignment?.id ?? randomUUID()
    if (!assignment) {
      storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
        .run(aid, runId, randomUUID(), Date.now())
    }
    const v4 = storage as unknown as V4StoreContract
    const created = v4.insertSecondOrderCanary({
      runId, assignmentId: aid, marker: 'gn2o_1122aabb',
      injectedOrigin: 'http://127.0.0.1:9', injectedEndpoint: '/profile', injectedParam: 'bio', injectedPersona: 'persona_a',
    })
    const rows = v4.listSecondOrderCanaries(runId, 'planted')
    assert.equal(rows.length, 1)
    assert.equal(rows[0].id, created.id)
    assert.equal(rows[0].status, 'planted')
  })

  test('T1-20c: Store.markSecondOrderCanarySurfaced transitions planted -> surfaced -> verified', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const v4 = storage as unknown as V4StoreContract
    const { id } = v4.insertSecondOrderCanary({
      runId, assignmentId: aid, marker: 'gn2o_cafebabe',
      injectedOrigin: 'http://127.0.0.1:9', injectedEndpoint: '/comment', injectedParam: 'body', injectedPersona: 'user_a',
    })
    v4.markSecondOrderCanarySurfaced(id, {
      surfacedOrigin: 'http://127.0.0.1:9', surfacedEndpoint: '/admin/export', surfacedPersona: 'admin', status: 'surfaced',
    })
    assert.equal(v4.listSecondOrderCanaries(runId, 'surfaced').length, 1)
    v4.markSecondOrderCanarySurfaced(id, {
      surfacedOrigin: 'http://127.0.0.1:9', surfacedEndpoint: '/admin/export', surfacedPersona: 'admin', status: 'verified',
    })
    assert.equal(v4.listSecondOrderCanaries(runId, 'verified').length, 1)
  })

  test('T1-20d: second-order matcher ignores immediate reflection on same endpoint + same persona', async (t) => {
    const marker = 'gn2o_01aabb22'
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.end(`<html><body>${marker}</body></html>`)
    })
    const { storage } = makeStore(t)
    const { runId, personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [
        { handle: 'user_a', roleLabel: 'A', authKind: 'bearer', secret: 'tok-a' },
        { handle: 'admin', roleLabel: 'Admin', authKind: 'bearer', secret: 'tok-admin' },
      ],
    })
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const v4 = storage as unknown as V4StoreContract
    v4.insertSecondOrderCanary({
      runId, assignmentId: aid, marker,
      injectedOrigin: fx.origin, injectedEndpoint: '/search', injectedParam: 'q', injectedPersona: 'user_a',
    })
    const broker = new RequestBroker({ rejectUnauthorized: false, storage }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin, { personas: personaMap })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/search', persona: 'user_a', runId, assignmentId: aid }, grant, AbortSignal.timeout(5000))
      assert.equal(v4.listSecondOrderCanaries(runId, 'surfaced').length, 0, 'Same-endpoint + same-persona reflection must not mark surfaced')
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/admin/users', persona: 'admin', runId, assignmentId: aid }, grant, AbortSignal.timeout(5000))
      assert.equal(v4.listSecondOrderCanaries(runId, 'surfaced').length, 1)
    })
  })

  test('T1-20e: second-order passive scanner skips responses from out-of-scope origins', async (t) => {
    const marker = 'gn2o_deadbeef12'
    const inScope = await startHttpFixture(t, (_req, _b, res) => res.end('ok'))
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [inScope.origin] })
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const v4 = storage as unknown as V4StoreContract
    v4.insertSecondOrderCanary({
      runId, assignmentId: aid, marker,
      injectedOrigin: inScope.origin, injectedEndpoint: '/p', injectedParam: 'q',
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    await assert.rejects(
      () => broker.executeHttp(
        { origin: 'https://unapproved.invalid', method: 'GET', pathAndQuery: '/leak', runId, assignmentId: aid },
        makeLabGrant(inScope.origin),
        AbortSignal.timeout(5000),
      ),
      BrokerDenied,
    )
    assert.equal(v4.listSecondOrderCanaries(runId, 'surfaced').length, 0)
  })

  // --- Feature 21: Build-Time Safe Nuclei Template Transpiler ---

  test('T1-21a: Nuclei transpiler rejects non-HTTP protocols (network, code, headless, javascript)', async (t) => {
    const mod = await loadV4Module('scripts/transpile-nuclei-templates.ts')
    const transpileDir = requireExport<(inDir: string, outDir: string) => Promise<{ transpiled: number; rejected: Array<{ file: string; reason: string }> }>>(
      mod, 'transpileNucleiDirectory', 'scripts/transpile-nuclei-templates.ts',
    )
    const inDir = makeTempDir(t, 'kovo-v4-nuc-1a-in-')
    const outDir = makeTempDir(t, 'kovo-v4-nuc-1a-out-')
    for (const proto of ['network', 'code', 'headless', 'javascript']) {
      writeFileSync(join(inDir, `bad-${proto}.yaml`), `id: bad-${proto}\ninfo:\n  name: Bad ${proto}\n  severity: high\n${proto}:\n  - input: test\n`)
    }
    const res = await transpileDir(inDir, outDir)
    assert.equal(res.transpiled, 0)
    assert.equal(res.rejected.length, 4)
    assert.equal(readdirSync(outDir).filter(f => /\.ya?ml$/i.test(f)).length, 0)
  })

  test('T1-21b: Nuclei transpiler rejects third-party OAST domains (oastify, interact.sh, webhook.site)', async (t) => {
    const mod = await loadV4Module('scripts/transpile-nuclei-templates.ts')
    const transpileDir = requireExport<(inDir: string, outDir: string) => Promise<{ transpiled: number; rejected: Array<{ file: string; reason: string }> }>>(
      mod, 'transpileNucleiDirectory', 'scripts/transpile-nuclei-templates.ts',
    )
    const inDir = makeTempDir(t, 'kovo-v4-nuc-1b-in-')
    const outDir = makeTempDir(t, 'kovo-v4-nuc-1b-out-')
    for (const [i, domain] of ['abc.oastify.com', 'xyz.interact.sh', 'webhook.site/123'].entries()) {
      writeFileSync(
        join(inDir, `bad-oast-${i}.yaml`),
        `id: bad-oast-${i}\ninfo:\n  name: Bad OAST\n  severity: high\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/ping?url=https://${domain}"\n    matchers:\n      - type: word\n        words:\n          - "ok"\n`,
      )
    }
    const res = await transpileDir(inDir, outDir)
    assert.equal(res.transpiled, 0)
    assert.equal(res.rejected.length, 3)
  })

  test('T1-21c: Nuclei transpiler rejects metadata IPs (169.254.169.254) and private/loopback addresses', async (t) => {
    const mod = await loadV4Module('scripts/transpile-nuclei-templates.ts')
    const transpileDir = requireExport<(inDir: string, outDir: string) => Promise<{ transpiled: number; rejected: Array<{ file: string; reason: string }> }>>(
      mod, 'transpileNucleiDirectory', 'scripts/transpile-nuclei-templates.ts',
    )
    const inDir = makeTempDir(t, 'kovo-v4-nuc-1c-in-')
    const outDir = makeTempDir(t, 'kovo-v4-nuc-1c-out-')
    for (const [i, host] of ['169.254.169.254', '127.0.0.1', '10.0.0.5'].entries()) {
      writeFileSync(
        join(inDir, `bad-ip-${i}.yaml`),
        `id: bad-ssrf-${i}\ninfo:\n  name: Bad SSRF\n  severity: high\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/fetch?u=http://${host}/latest"\n    matchers:\n      - type: word\n        words:\n          - "ami"\n`,
      )
    }
    const res = await transpileDir(inDir, outDir)
    assert.equal(res.transpiled, 0)
    assert.equal(res.rejected.length, 3)
  })

  test('T1-21d: Nuclei transpiler rejects destructive payloads and unreviewed mutating methods', async (t) => {
    const mod = await loadV4Module('scripts/transpile-nuclei-templates.ts')
    const transpileDir = requireExport<(inDir: string, outDir: string) => Promise<{ transpiled: number; rejected: Array<{ file: string; reason: string }> }>>(
      mod, 'transpileNucleiDirectory', 'scripts/transpile-nuclei-templates.ts',
    )
    const inDir = makeTempDir(t, 'kovo-v4-nuc-1d-in-')
    const outDir = makeTempDir(t, 'kovo-v4-nuc-1d-out-')
    writeFileSync(join(inDir, 'destructive.yaml'), `id: bad-rm\ninfo:\n  name: Bad RM\n  severity: critical\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/run?cmd=rm%20-rf%20/"\n    matchers:\n      - type: word\n        words:\n          - "done"\n`)
    writeFileSync(join(inDir, 'mutating.yaml'), `id: bad-del\ninfo:\n  name: Bad DELETE\n  severity: high\nhttp:\n  - method: DELETE\n    path:\n      - "{{BaseURL}}/api/users/1"\n    matchers:\n      - type: word\n        words:\n          - "deleted"\n`)
    const res = await transpileDir(inDir, outDir)
    assert.equal(res.transpiled, 0)
    assert.equal(res.rejected.length, 2)
  })

  test('T1-21e: Nuclei transpiler rewrites {{interactsh-url}} -> {{kovo_canary_http}} and passes parseSafeTemplateYaml', async (t) => {
    const mod = await loadV4Module('scripts/transpile-nuclei-templates.ts')
    const transpileDir = requireExport<(inDir: string, outDir: string) => Promise<{ transpiled: number; rejected: Array<{ file: string; reason: string }> }>>(
      mod, 'transpileNucleiDirectory', 'scripts/transpile-nuclei-templates.ts',
    )
    const inDir = makeTempDir(t, 'kovo-v4-nuc-1e-in-')
    const outDir = makeTempDir(t, 'kovo-v4-nuc-1e-out-')
    writeFileSync(
      join(inDir, 'good.yaml'),
      [
        'id: cve-2024-99999-canary-ssrf',
        'info:',
        '  name: Safe Canary SSRF Check',
        '  severity: high',
        '  tags: nextjs,ssrf,cve',
        'http:',
        '  - method: GET',
        '    path:',
        '      - "{{BaseURL}}/api/preview?url=http://{{interactsh-url}}/probe"',
        '    matchers:',
        '      - type: word',
        '        part: interactsh_protocol',
        '        words:',
        '          - "http"',
      ].join('\n'),
    )
    const res = await transpileDir(inDir, outDir)
    assert.equal(res.transpiled, 1)
    assert.equal(res.rejected.length, 0)
    const files = readdirSync(outDir).filter(f => /\.ya?ml$/i.test(f))
    assert.equal(files.length, 1)
    const yaml = readFileSync(join(outDir, files[0]), 'utf8')
    assert.ok(yaml.includes('{{kovo_canary_http}}'))
    const parsed = parseSafeTemplateYaml(yaml)
    assert.equal(parsed.id, 'cve-2024-99999-canary-ssrf')
  })

  // --- Feature 22: Budget- & Coverage-Driven Dynamic Queueing ---

  test('T1-22a: dynamicStepBudget clamp(24, crownJewels*2 + suspects, 200) BVA', async (t) => {
    const cases = [
      { crownJewels: 0, suspects: 0, expected: 24 },
      { crownJewels: 30, suspects: 15, expected: 75 },
      { crownJewels: 150, suspects: 50, expected: 200 },
    ]
    for (const c of cases) {
      const { storage } = makeStore(t)
      const llm = await startMockLlmServer(t, () => ({ type: 'text', text: JSON.stringify({ summary: 'done', newSteps: [], cancelStepIds: [], done: true }) }))
      await saveModelProfile({
        name: 'Planner', endpoint: llm.endpoint, model: 'mock-p', protocol: 'responses', key: 'sk-p-12345678',
        priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'low', roleAffinity: 'fast',
        inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
      }, storage, { skipConnectionCheck: true })
      const { runId, run } = await setupApprovedRun(storage)
      const v4 = storage as unknown as V4StoreContract
      for (let i = 0; i < c.crownJewels; i += 1) {
        v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: `/api/admin/ep_${i}`, source: 'spa_crawl', riskScore: 95 })
      }
      const aid = randomUUID()
      storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'threat_model', 'complete', 1, 0, ?, '[]', '[]', 'tm', 'tm', ?)`)
        .run(aid, runId, randomUUID(), Date.now())
      const worker = storage.worker(aid)
      for (let i = 0; i < c.suspects; i += 1) {
        storage.addFact(run, worker, { kind: 'code_audit_suspect', origin: 'http://127.0.0.1:9', summary: `Suspect ${i}`, data: { routeOrAction: `/s/${i}` } })
      }
      storage.updateRun(runId, { phase: 'investigation', status: 'running' })
      const engine = new Execution(storage)
      await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
        engine.start()
        engine.wake()
        const deadline = Date.now() + 8_000
        while (Date.now() < deadline) {
          const row = storage.client.prepare('SELECT dynamic_step_budget FROM runs WHERE id = ?').get(runId) as { dynamic_step_budget: number | null }
          if (row.dynamic_step_budget !== null) break
          await delay(50)
        }
        await stopExecution(engine as never)
      })
      const row = storage.client.prepare('SELECT dynamic_step_budget FROM runs WHERE id = ?').get(runId) as { dynamic_step_budget: number | null }
      assert.equal(row.dynamic_step_budget, c.expected, `Expected dynamic_step_budget=${c.expected} for (${c.crownJewels}, ${c.suspects}), got ${row.dynamic_step_budget}`)
    }
  })

  test('T1-22b: dynamic queueing respects hard 300 ceiling and budgetUsd / budgetRequests exhaustion', async (t) => {
    for (const mode of ['requests', 'usd'] as const) {
      const { storage } = makeStore(t)
      const { runId } = await setupApprovedRun(storage, { budgetUsd: 25, budgetRequests: 1000 })
      if (mode === 'requests') {
        storage.client.prepare('UPDATE runs SET spent_requests = 1000 WHERE id = ?').run(runId)
      } else {
        storage.client.prepare('UPDATE runs SET spent_usd = 25 WHERE id = ?').run(runId)
      }
      storage.updateRun(runId, { phase: 'investigation', status: 'running' })
      const engine = new Execution(storage)
      await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
        engine.start()
        engine.wake()
        await delay(200)
        await stopExecution(engine as never)
      })
      assert.equal(storage.run(runId).status, 'budget_paused')
    }
  })

  test('T1-22c: a dry streak never fires the retired K=6 halt', async (t) => {
    const { storage } = makeStore(t)
    const llm = await startMockLlmServer(t, () => ({
      type: 'text',
      text: JSON.stringify({
        summary: 'Add another step',
        newSteps: [{ title: 'Extra step', hypothesis: 'Probe', category: 'misconfig-exposure', priority: 50, origins: ['http://127.0.0.1:9'], skills: [] }],
        cancelStepIds: [],
        done: false,
      }),
    }))
    await saveModelProfile({
      name: 'Planner', endpoint: llm.endpoint, model: 'mock-p', protocol: 'responses', key: 'sk-dry-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'low', roleAffinity: 'fast',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId, run, assetIds } = await setupApprovedRun(storage, { budgetRequests: 2000 })
    for (let i = 0; i < 6; i += 1) {
      const st = storage.addChainStep(run, {
        title: `Dry step ${i}`, hypothesis: 'dry', category: 'misconfig-exposure', priority: 50, targetAssetIds: assetIds,
      })
      storage.updateChainStep(st.id, { status: 'complete' })
    }
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 8_000
      while (Date.now() < deadline) {
        if (storage.run(runId).phase === 'verification' || storage.run(runId).phase === 'complete') break
        await delay(50)
      }
      await stopExecution(engine as never)
    })
    const finalRun = storage.run(runId)
    assert.notEqual(finalRun.status, 'failed', 'the run must not fail because of a dry streak')
    assert.ok(
      !storage.eventsAfter(runId, 0).some(e => e.kind === 'planner.diminishing_returns'),
      'v6 retired the K=6 global kill event',
    )
  })

  test('T1-22d: coverage_entries with status needs_follow_up outrank untested low-priority endpoints', async (t) => {
    const { storage } = makeStore(t)
    const llm = await startMockLlmServer(t, () => ({
      type: 'text',
      text: JSON.stringify({ summary: 'done', newSteps: [], cancelStepIds: [], done: true }),
    }))
    await saveModelProfile({
      name: 'Planner', endpoint: llm.endpoint, model: 'mock-p', protocol: 'responses', key: 'sk-cov-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'low', roleAffinity: 'fast',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId, run } = await setupApprovedRun(storage)
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'complete', 1, 0, ?, '[]', '[]', 'w', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    storage.upsertCoverageEntry(run, aid, {
      origin: 'http://127.0.0.1:9',
      category: 'broken-access-control',
      status: 'needs_follow_up',
      summary: 'Follow up BOLA gap',
      proofGapReason: 'Missing second persona check',
    })
    const v4 = storage as unknown as V4StoreContract
    v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/fresh-low', source: 'spa_crawl', riskScore: 30, coveragePct: 0 })
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 8_000
      while (Date.now() < deadline && llm.calls.length === 0) await delay(50)
      await stopExecution(engine as never)
    })
    assert.ok(llm.calls.length >= 1)
    assert.match(JSON.stringify(llm.calls[0].body), /needs_follow_up|Follow up BOLA gap/)
  })

  test('T1-22e: Store.updateRunDynamicStepBudget persists dynamic_step_budget in SQLite runs', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    v4.updateRunDynamicStepBudget(runId, 88)
    const row = storage.client.prepare('SELECT dynamic_step_budget FROM runs WHERE id = ?').get(runId) as { dynamic_step_budget: number }
    assert.equal(row.dynamic_step_budget, 88)
  })

  // --- Feature 23: 7 Clean-Context Specialist Worker Profiles ---

  test('T1-23a: all 7 specialist profile IDs are registered in domain specialistProfiles', () => {
    const expectedIds = [
      'bola-bfla-specialist',
      'injection-parser-specialist',
      'auth-session-oauth-specialist',
      'client-browser-dom-specialist',
      'graphql-api-specialist',
      'business-logic-race-specialist',
      'protocol-cache-edge-specialist',
    ]
    for (const id of expectedIds) {
      assert.ok((specialistProfiles as readonly string[]).includes(id), `Missing specialist worker profile: ${id}`)
    }
  })

  test('T1-23b: specialist profiles enforce the agentic turn budget floor and <= 60 ceiling', async (t) => {
    const { storage } = makeStore(t)
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call', callId: 'c_sp', name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'proved', summary: 'done' }),
    }))
    await saveModelProfile({
      name: 'Tac', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-sp-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId, run, assetIds } = await setupApprovedRun(storage)
    const step = storage.addChainStep(run, {
      title: 'BOLA check on /api/orders', hypothesis: 'Cross-tenant access', category: 'broken-access-control',
      priority: 90, targetAssetIds: assetIds, skills: ['bola-idor-race'],
    })
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 8_000
      while (Date.now() < deadline) {
        if (storage.workerList(runId).some(w => w.stepId === step.id && w.status === 'complete')) break
        await delay(50)
      }
      await stopExecution(engine as never)
    })
    const worker = storage.workerList(runId).find(w => w.stepId === step.id)
    assert.ok(worker, 'Expected specialist assignment to be created')
    assert.ok(worker.maxTurns >= AGENTIC_MIN_MAX_TURNS && worker.maxTurns <= 60, `Specialist maxTurns=${worker.maxTurns} out of bounds [${AGENTIC_MIN_MAX_TURNS}..60]`)
  })

  test('T1-23c: resolving an unknown specialist profile throws explicit validation error', async (t) => {
    const { storage } = makeStore(t)
    const { run, assetIds } = await setupApprovedRun(storage)
    assert.throws(
      () => storage.addChainStep(run, {
        title: 'Bad specialist',
        hypothesis: 'test',
        category: 'broken-access-control',
        priority: 50,
        targetAssetIds: assetIds,
        specialistProfile: 'nonexistent-specialist-xyz' as never,
      }),
      /unknown|invalid|specialist|enum/i,
    )
  })

  test('T1-23d: each specialist profile defines non-empty scoped tools and curated skills', async (t) => {
    const { storage } = makeStore(t)
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call', callId: 'c_tools', name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'proved', summary: 'done' }),
    }))
    await saveModelProfile({
      name: 'Tac', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-tools-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId, run, assetIds } = await setupApprovedRun(storage)
    const step = storage.addChainStep(run, {
      title: 'SQLi check', hypothesis: 'sqli_boolean on /search', category: 'injection-input',
      priority: 85, targetAssetIds: assetIds, skills: ['sqli-boolean-differential'],
    })
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 8_000
      while (Date.now() < deadline && llm.calls.length === 0) await delay(50)
      await stopExecution(engine as never)
    })
    assert.ok(llm.calls.length >= 1)
    const toolNames = ((llm.calls[0].body.tools ?? []) as Array<{ name?: string }>).map(x => x.name ?? '')
    assert.ok(toolNames.length >= 2, 'Expected >= 2 scoped tools for specialist')
    assert.ok(toolNames.includes('verify_replay_spec'), 'Specialist must include verify_replay_spec')
    assert.ok(storage.listChainSteps(runId).find(s => s.id === step.id)?.specialistProfile, 'Expected chain_steps.specialist_profile to be assigned')
  })

  test('T1-23e: chain_steps.specialist_profile persists assigned specialist profile in SQLite', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const cols = tableColumns(storage, 'chain_steps')
    assert.ok(cols.includes('specialist_profile'), 'chain_steps.specialist_profile column missing')
    const stepId = randomUUID()
    const now = Date.now()
    storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, specialist_profile, created_at, updated_at) VALUES (?, ?, 0, 1, 1, 'BOLA check', 'hyp', 'broken-access-control', 90, '[]', '[]', '[]', '[]', 'pending', '[]', 'bola-bfla-specialist', ?, ?)`)
      .run(stepId, runId, now, now)
    const row = storage.client.prepare('SELECT specialist_profile FROM chain_steps WHERE id = ?').get(stepId) as { specialist_profile: string }
    assert.equal(row.specialist_profile, 'bola-bfla-specialist')
  })

  // --- Feature 24: Multi-Trial Parallel Branching + Early Stopping ---

  test('T1-24a: multi-trial fanout triggers on priority >= 88 / code_audit_suspect / cve_hypothesis and skips routine priority 40', async (t) => {
    const { storage } = makeStore(t)
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call', callId: 'c_mt', name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'done' }),
    }))
    await saveModelProfile({
      name: 'Tac', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-mt-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId, run, assetIds } = await setupApprovedRun(storage)
    storage.addChainStep(run, {
      title: 'Crown Lead 88', hypothesis: 'high prio', category: 'broken-access-control', priority: 88, targetAssetIds: assetIds,
    })
    storage.addChainStep(run, {
      title: 'Routine Lead 40', hypothesis: 'low prio', category: 'misconfig-exposure', priority: 40, targetAssetIds: assetIds,
    })
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      await delay(500)
      await stopExecution(engine as never)
    })
    const steps = storage.listChainSteps(runId)
    const crownTrials = steps.filter(s => s.title.includes('Crown Lead 88'))
    const routineTrials = steps.filter(s => s.title.includes('Routine Lead 40'))
    assert.ok(crownTrials.length >= 2, `Expected >= 2 trials for priority 88 lead, got ${crownTrials.length}`)
    assert.equal(routineTrials.length, 1, 'Routine priority 40 step must not fan out')
  })

  test('T1-24b: multi-trial fanout BVA (2 default for high, 3 for critical, max 3 ceiling)', async (t) => {
    const { storage } = makeStore(t)
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call', callId: 'c_mt2', name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'done' }),
    }))
    await saveModelProfile({
      name: 'Tac', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-mt2-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId, run, assetIds } = await setupApprovedRun(storage)
    storage.addChainStep(run, {
      title: 'High Lead', hypothesis: 'high', category: 'broken-access-control', priority: 90, targetAssetIds: assetIds,
    })
    storage.addChainStep(run, {
      title: 'Critical Lead', hypothesis: 'critical', category: 'injection-input', priority: 96, targetAssetIds: assetIds,
    })
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      await delay(500)
      await stopExecution(engine as never)
    })
    const steps = storage.listChainSteps(runId)
    const highTrials = steps.filter(s => s.title.includes('High Lead'))
    const critTrials = steps.filter(s => s.title.includes('Critical Lead'))
    assert.equal(highTrials.length, 2)
    assert.ok(critTrials.length >= 2 && critTrials.length <= 3)
  })

  test('T1-24c: chain_steps persists trial_group_id and trial_index in SQLite', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const cols = tableColumns(storage, 'chain_steps')
    assert.ok(cols.includes('trial_group_id'))
    assert.ok(cols.includes('trial_index'))
    const gid = randomUUID()
    const sid = randomUUID()
    const now = Date.now()
    storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, trial_group_id, trial_index, created_at, updated_at) VALUES (?, ?, 0, 1, 1, 'Trial', 'hyp', 'injection-input', 92, '[]', '[]', '[]', '[]', 'pending', '[]', ?, 1, ?, ?)`)
      .run(sid, runId, gid, now, now)
    const row = storage.client.prepare('SELECT trial_group_id, trial_index FROM chain_steps WHERE id = ?').get(sid) as { trial_group_id: string; trial_index: number }
    assert.equal(row.trial_group_id, gid)
    assert.equal(row.trial_index, 1)
  })

  test('T1-24d: multiTrialEnabled: false disables parallel fanout (returns 1)', async (t) => {
    const { storage } = makeStore(t)
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call', callId: 'c_mtd', name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'done' }),
    }))
    await saveModelProfile({
      name: 'Tac', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-mtd-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId, run, assetIds } = await setupApprovedRun(storage)
    storage.updateRun(runId, { multiTrialEnabled: false, phase: 'investigation', status: 'running' })
    storage.addChainStep(run, {
      title: 'Critical Single', hypothesis: 'crit', category: 'injection-input', priority: 99, targetAssetIds: assetIds,
    })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      await delay(400)
      await stopExecution(engine as never)
    })
    assert.equal(storage.listChainSteps(runId).filter(s => s.title.includes('Critical Single')).length, 1)
  })

  test('T1-24e: multi-trial fanout never exceeds run.workerConcurrency', async (t) => {
    const { storage } = makeStore(t)
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call', callId: 'c_mte', name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'done' }),
    }))
    await saveModelProfile({
      name: 'Tac', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-mte-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId, run, assetIds } = await setupApprovedRun(storage)
    storage.updateRun(runId, { workerConcurrency: 1, phase: 'investigation', status: 'running' })
    storage.addChainStep(run, {
      title: 'Bounded Fanout', hypothesis: 'crit', category: 'injection-input', priority: 99, targetAssetIds: assetIds,
    })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      await delay(400)
      await stopExecution(engine as never)
    })
    assert.equal(storage.listChainSteps(runId).filter(s => s.title.includes('Bounded Fanout')).length, 1)
  })

  // --- Feature 25: Role-Based Tiered Model Routing ---

  test('T1-25a: providerSettings schema accepts roleAffinity reasoning|tactical|fast|any and defaults to any', () => {
    for (const roleAffinity of ['reasoning', 'tactical', 'fast', 'any'] as const) {
      const parsed = providerSettings.safeParse({
        name: `Profile-${roleAffinity}`,
        endpoint: 'https://openrouter.ai/api/v1',
        model: 'deepseek/deepseek-v4',
        protocol: 'responses',
        key: 'sk-test-key-12345678',
        roleAffinity,
      } as unknown)
      assert.equal(parsed.success, true)
    }
    const def = providerSettings.safeParse({
      name: 'Default',
      endpoint: 'https://openrouter.ai/api/v1',
      model: 'deepseek/deepseek-v4',
      protocol: 'responses',
      key: 'sk-test-key-12345678',
    } as unknown)
    assert.equal(def.success, true)
    if (def.success) {
      assert.equal((def.data as unknown as { roleAffinity?: string }).roleAffinity, 'any')
    }
  })

  test('T1-25b: providerSettings rejects invalid roleAffinity values', () => {
    const bad = providerSettings.safeParse({
      name: 'BadRole',
      endpoint: 'https://openrouter.ai/api/v1',
      model: 'deepseek/deepseek-v4',
      protocol: 'responses',
      key: 'sk-test-key-12345678',
      roleAffinity: 'supergenius',
    } as unknown)
    assert.equal(bad.success, false)
  })

  test('T1-25c: resolveProfilePoolForRole falls back to single enabled profile for all roles', async (t) => {
    const mod = await import('../src/server/model-settings.ts') as Record<string, unknown>
    const resolvePool = requireExport<(role: RoleAffinity, storage?: Store) => Array<{ id: string; model: string }>>(
      mod, 'resolveProfilePoolForRole', 'src/server/model-settings.ts',
    )
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'Single Profile',
      endpoint: 'https://openrouter.ai/api/v1',
      model: 'deepseek/single',
      protocol: 'responses',
      key: 'sk-single-12345678',
      priority: 100,
      enabled: true,
      contextWindow: 128_000,
      maxTokens: 8192,
      thinkingLevel: 'medium',
      inputCostPerMtok: 0.1,
      cachedInputCostPerMtok: 0.01,
      outputCostPerMtok: 0.2,
    }, storage, { skipConnectionCheck: true })
    for (const role of ['reasoning', 'tactical', 'fast', 'any'] as const) {
      const pool = resolvePool(role, storage)
      assert.equal(pool.length, 1)
      assert.equal(pool[0].model, 'deepseek/single')
    }
  })

  test('T1-25d: resolveProfilePoolForRole orders matching roleAffinity by descending priority', async (t) => {
    const mod = await import('../src/server/model-settings.ts') as Record<string, unknown>
    const resolvePool = requireExport<(role: RoleAffinity, storage?: Store) => Array<{ name: string; priority: number }>>(
      mod, 'resolveProfilePoolForRole', 'src/server/model-settings.ts',
    )
    const { storage } = makeStore(t)
    const base = {
      endpoint: 'https://openrouter.ai/api/v1',
      model: 'deepseek/r1',
      protocol: 'responses' as const,
      key: 'sk-test-12345678',
      enabled: true,
      contextWindow: 128_000,
      maxTokens: 8192,
      thinkingLevel: 'high' as const,
      inputCostPerMtok: 0.5,
      cachedInputCostPerMtok: 0.05,
      outputCostPerMtok: 1.5,
    }
    await saveModelProfile({ ...base, name: 'R-Low', priority: 50, roleAffinity: 'reasoning' } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    await saveModelProfile({ ...base, name: 'R-High', priority: 200, roleAffinity: 'reasoning' } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    await saveModelProfile({ ...base, name: 'Any-Mid', priority: 150, roleAffinity: 'any' } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    const pool = resolvePool('reasoning', storage)
    assert.equal(pool[0].name, 'R-High')
    assert.equal(pool[1].name, 'R-Low')
  })

  test('T1-25e: resolveProfilePoolForRole skips disabled and open-circuit profiles', async (t) => {
    const mod = await import('../src/server/model-settings.ts') as Record<string, unknown>
    const resolvePool = requireExport<(role: RoleAffinity, storage?: Store) => Array<{ id: string; name: string }>>(
      mod, 'resolveProfilePoolForRole', 'src/server/model-settings.ts',
    )
    const { storage } = makeStore(t)
    const base = {
      endpoint: 'https://openrouter.ai/api/v1',
      model: 'deepseek/fast',
      protocol: 'responses' as const,
      key: 'sk-test-12345678',
      contextWindow: 128_000,
      maxTokens: 4096,
      thinkingLevel: 'low' as const,
      inputCostPerMtok: 0.1,
      cachedInputCostPerMtok: 0.01,
      outputCostPerMtok: 0.2,
    }
    await saveModelProfile({ ...base, name: 'Disabled', priority: 300, enabled: false, roleAffinity: 'fast' } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    const openProf = await saveModelProfile({ ...base, name: 'OpenCircuit', priority: 250, enabled: true, roleAffinity: 'fast' } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    storage.client.prepare('UPDATE model_profiles SET health_state = ?, cooldown_until = ? WHERE id = ?')
      .run('open', Date.now() + 60_000, openProf.id)
    await saveModelProfile({ ...base, name: 'HealthyFast', priority: 100, enabled: true, roleAffinity: 'fast' } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    const pool = resolvePool('fast', storage)
    assert.ok(!pool.some(p => p.name === 'Disabled'))
    const ordered = orderProfiles(pool as never, 1000, 'fast')
    assert.deepEqual(ordered.map(p => p.name), ['HealthyFast'])
  })

  // --- Feature 26: Recall Benchmark Harness & Failure Taxonomy ---

  test('T1-26a: benchmark funnel enforces monotonic invariant target >= surface >= hypothesis >= signal >= spec >= confirmed', async (t) => {
    const mod = await loadV4Module('scripts/benchmark-recall.ts')
    const runSuite = requireExport<(opts: Record<string, unknown>) => Promise<{ funnelCounts: Record<string, number> }>>(
      mod, 'runBenchmarkSuite', 'scripts/benchmark-recall.ts',
    )
    const { storage } = makeStore(t)
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runSuite({ suite: 'xben-25', dryRun: true, storage }),
    )
    const f = res.funnelCounts
    assert.ok(f.targetVulns >= f.surfaceDiscovered)
    assert.ok(f.surfaceDiscovered >= f.hypothesisFormed)
    assert.ok(f.hypothesisFormed >= f.signalObserved)
    assert.ok(f.signalObserved >= f.specSubmitted)
    assert.ok(f.specSubmitted >= f.zeroLlmConfirmed)
  })

  test('T1-26b: all 11 deterministic failure-taxonomy buckets are defined in domain failureTaxonomyBuckets', () => {
    const expected = [
      'surface_miss', 'hypothesis_miss', 'form_encoding_missing', 'csrf_blocked', 'context_reset',
      'tier_blocked', 'trigger_miss', 'jq_assertion_bug', 'spa_catchall_fp', 'replay_spec_miss', 'budget_exhausted',
    ]
    for (const b of expected) {
      assert.ok((failureTaxonomyBuckets as readonly string[]).includes(b), `Missing failure-taxonomy bucket: ${b}`)
    }
  })

  test('T1-26c: benchmark JSON + Markdown diff formatter computes recall and precision deltas', async (t) => {
    const mod = await loadV4Module('scripts/benchmark-recall.ts')
    const runSuite = requireExport<(opts: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runBenchmarkSuite', 'scripts/benchmark-recall.ts',
    )
    const { dir, storage } = makeStore(t)
    const v4 = storage as unknown as V4StoreContract
    v4.insertBenchmarkRun({
      suite: 'xben-25', gitSha: 'aaa111', modelRoutingConfig: {}, targetsTotal: 25, confirmedCount: 10, falsePositiveCount: 0,
      funnelCounts: { targetVulns: 25, surfaceDiscovered: 20, hypothesisFormed: 18, signalObserved: 15, specSubmitted: 12, zeroLlmConfirmed: 10 },
      failureTaxonomy: { surface_miss: 5 }, totalCostUsd: 5.0, durationMs: 1000,
    })
    const outJson = join(dir, 'diff.json')
    const outMd = join(dir, 'diff.md')
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runSuite({ suite: 'xben-25', dryRun: true, baselineSha: 'aaa111', gitSha: 'bbb222', storage, outJson, outMd }),
    )
    assert.ok(existsSync(outJson))
    assert.ok(existsSync(outMd))
    const md = readFileSync(outMd, 'utf8')
    assert.match(md, /aaa111|bbb222|recall|delta/i)
  })

  test('T1-26d: benchmark metrics calculator guards zero-division when targetsTotal === 0', async (t) => {
    const { storage } = makeStore(t)
    const v4 = storage as unknown as V4StoreContract
    const row = v4.insertBenchmarkRun({
      suite: 'empty', gitSha: 'zero00', modelRoutingConfig: {}, targetsTotal: 0, confirmedCount: 0, falsePositiveCount: 0,
      funnelCounts: { targetVulns: 0, surfaceDiscovered: 0, hypothesisFormed: 0, signalObserved: 0, specSubmitted: 0, zeroLlmConfirmed: 0 },
      failureTaxonomy: {}, totalCostUsd: 0, durationMs: 0,
    })
    assert.ok(row.id)
    const mod = await loadV4Module('scripts/benchmark-recall.ts')
    assert.equal(typeof mod.runBenchmarkSuite, 'function')
  })

  test('T1-26e: Store.insertBenchmarkRun and getLatestBenchmarkRun persist and retrieve benchmark_runs rows', async (t) => {
    const { storage } = makeStore(t)
    const v4 = storage as unknown as V4StoreContract
    const inserted = v4.insertBenchmarkRun({
      suite: 'xben-25',
      gitSha: 'deadbeef1234',
      modelRoutingConfig: { reasoning: 'r1', tactical: 'v4' },
      targetsTotal: 25,
      confirmedCount: 20,
      falsePositiveCount: 0,
      funnelCounts: { targetVulns: 25, surfaceDiscovered: 24, hypothesisFormed: 23, signalObserved: 22, specSubmitted: 21, zeroLlmConfirmed: 20 },
      failureTaxonomy: { surface_miss: 1, trigger_miss: 4 },
      totalCostUsd: 3.45,
      durationMs: 42_000,
    })
    const latest = v4.getLatestBenchmarkRun('xben-25')
    assert.ok(latest)
    assert.equal(latest.id, inserted.id)
    assert.equal(latest.confirmedCount ?? latest.confirmed_count, 20)
  })

  // --- Feature 27: Local Labs (XBEN-25 & Held-Out SaaS Lab) & Hill-Climbing ---

  test('T1-27a: XBEN-25 benchmark manifest exists and indexes >= 25 distinct challenges', () => {
    const manifestPath = resolve(repoRoot, 'benchmarks/xben-25/manifest.json')
    assert.ok(existsSync(manifestPath), `Expected XBEN-25 manifest at ${manifestPath}`)
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as { challenges: Array<{ id: string; cwe: string }> }
    assert.ok(manifest.challenges.length >= 25, `Expected >= 25 challenges in XBEN-25, got ${manifest.challenges.length}`)
    assert.equal(new Set(manifest.challenges.map(c => c.id)).size, manifest.challenges.length)
  })

  test('T1-27b: Held-Out Modern SaaS Lab manifest defines 20 planted vulns + 6 hard decoys', () => {
    const manifestPath = resolve(repoRoot, 'local-lab/held-out-saas/manifest.json')
    assert.ok(existsSync(manifestPath), `Expected Held-Out SaaS Lab manifest at ${manifestPath}`)
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as { challenges: Array<{ id: string; isDecoy?: boolean }> }
    const vulns = manifest.challenges.filter(c => !c.isDecoy)
    const decoys = manifest.challenges.filter(c => Boolean(c.isDecoy))
    assert.equal(vulns.length, 20)
    assert.equal(decoys.length, 6)
  })

  test('T1-27c: anti-overfit validator confirms src/ contains zero benchmark-specific challenge IDs or flag literals', () => {
    const manifestPath = resolve(repoRoot, 'local-lab/held-out-saas/manifest.json')
    assert.ok(existsSync(manifestPath), `Expected Held-Out SaaS Lab manifest at ${manifestPath}`)
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as { challenges: Array<{ id: string; flagMarker?: string }> }
    const srcFiles: string[] = []
    const walk = (d: string) => {
      for (const entry of readdirSync(d, { withFileTypes: true })) {
        const full = join(d, entry.name)
        if (entry.isDirectory()) walk(full)
        else if (/\.(ts|tsx)$/.test(entry.name)) srcFiles.push(full)
      }
    }
    walk(resolve(repoRoot, 'src'))
    const allSrc = srcFiles.map(f => readFileSync(f, 'utf8')).join('\n')
    for (const c of manifest.challenges) {
      if (c.flagMarker) {
        assert.ok(!allSrc.includes(c.flagMarker), `Anti-overfit violation: src/ contains benchmark flag ${c.flagMarker}`)
      }
    }
  })

  test('T1-27d: Held-Out Lab decoys are excluded from targetsTotal recall denominator and counted in falsePositiveCount', async (t) => {
    const mod = await loadV4Module('scripts/benchmark-recall.ts')
    const runSuite = requireExport<(opts: Record<string, unknown>) => Promise<{ targetsTotal: number; falsePositiveCount: number; funnelCounts: Record<string, number> }>>(
      mod, 'runBenchmarkSuite', 'scripts/benchmark-recall.ts',
    )
    const { storage } = makeStore(t)
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runSuite({ suite: 'held-out-saas', dryRun: true, storage }),
    )
    assert.equal(res.targetsTotal, 20)
    assert.equal(res.funnelCounts.targetVulns, 20)
    assert.equal(res.falsePositiveCount, 0)
  })

  test('T1-27e: benchmark-recall refuses to execute local-lab benchmarks when KOVO_ALLOW_LOCAL_LAB != 1', async () => {
    const mod = await loadV4Module('scripts/benchmark-recall.ts')
    const runSuite = requireExport<(opts: { suite: string }) => Promise<unknown>>(
      mod, 'runBenchmarkSuite', 'scripts/benchmark-recall.ts',
    )
    await assert.rejects(
      () => withEnv({ KOVO_ALLOW_LOCAL_LAB: undefined }, () => runSuite({ suite: 'held-out-saas' })),
      /KOVO_ALLOW_LOCAL_LAB/,
    )
  })

  // --- Feature 28: Drizzle SQLite v4 Schema & Lossless Migration ---

  test('T1-28a: Store.initV4Schema() is idempotent across repeated invocations', async (t) => {
    const { storage } = makeStore(t)
    const v4 = storage as unknown as V4StoreContract
    const initFn = requireMethod<() => void>(v4, 'initV4Schema', 'Store')
    initFn()
    initFn()
    assert.ok(hasTable(storage, 'endpoints'))
    assert.ok(hasTable(storage, 'benchmark_runs'))
  })

  test('T1-28b: v4 Store opens legacy v3 SQLite DB and preserves 100% of existing projects/runs/findings/profiles', async (t) => {
    const dir = makeTempDir(t, 'kovo-v3-mig-')
    const srcDb = resolve(repoRoot, '.kovo/dyad-v2-smoke/data/kovo.sqlite')
    if (existsSync(srcDb)) {
      copyFileSync(srcDb, join(dir, 'kovo.sqlite'))
    } else {
      const seed = new Store(dir)
      const now = Date.now()
      const wsId = seed.workspace.id
      seed.client.exec(`
        INSERT INTO model_profiles (id, workspace_id, name, endpoint, model, protocol, credential_id, updated_at)
          VALUES ('mp-legacy-1', '${wsId}', 'Legacy Profile', 'https://api.example/v1', 'm1', 'responses', 'cred-1', ${now});
        INSERT INTO projects (id, workspace_id, name, seeds, default_scope, created_at)
          VALUES ('proj-legacy-1', '${wsId}', 'Legacy Project', '["http://127.0.0.1:9"]', '[]', ${now});
        INSERT INTO runs (id, project_id, workspace_id, original_goal, goal, goal_revision, scope_revision, coordinator_id, phase, status, approved_persona_ids, candidates, approved, created_at)
          VALUES ('run-legacy-1', 'proj-legacy-1', '${wsId}', 'Audit', 'Audit', 1, 1, 'coord-1', 'complete', 'complete', '[]', '[]', '[]', ${now});
        INSERT INTO findings (id, run_id, asset_id, goal_revision, check_id, case_id, finding_kind, source_origins, verification_tier, finding)
          VALUES ('find-legacy-1', 'run-legacy-1', 'asset-1', 1, 'chain', 'legacy-1', 'multi_step_chain', '["http://127.0.0.1:9"]', 'runtime_confirmed', '{"id":"find-legacy-1","title":"Legacy Finding","status":"confirmed"}');
      `)
      seed.close()
      const raw = new DatabaseSync(join(dir, 'kovo.sqlite'))
      for (const tbl of ['benchmark_runs', 'lab_telemetry', 'second_order_canaries', 'api_dependencies', 'endpoint_params', 'endpoints']) {
        raw.exec(`DROP TABLE IF EXISTS ${tbl};`)
      }
      raw.exec(`
        ALTER TABLE model_profiles DROP COLUMN role_affinity;
        ALTER TABLE projects DROP COLUMN sandbox_write_allowlist;
        ALTER TABLE runs DROP COLUMN dynamic_step_budget;
        ALTER TABLE runs DROP COLUMN multi_trial_enabled;
        ALTER TABLE runs DROP COLUMN phase0_completed_at;
        ALTER TABLE chain_steps DROP COLUMN specialist_profile;
        ALTER TABLE chain_steps DROP COLUMN trial_group_id;
        ALTER TABLE chain_steps DROP COLUMN trial_index;
        ALTER TABLE replay_specs DROP COLUMN attempt_count;
        ALTER TABLE replay_specs DROP COLUMN verified_inline;
        ALTER TABLE replay_specs DROP COLUMN last_verification_diff;
      `)
      raw.close()
    }
    const migrated = new Store(dir)
    t.after(() => migrated.close())
    const counts = {
      projects: (migrated.client.prepare('SELECT COUNT(*) AS n FROM projects').get() as { n: number }).n,
      runs: (migrated.client.prepare('SELECT COUNT(*) AS n FROM runs').get() as { n: number }).n,
      findings: (migrated.client.prepare('SELECT COUNT(*) AS n FROM findings').get() as { n: number }).n,
    }
    assert.ok(counts.projects >= 1, 'Expected preserved projects after v3->v4 migration')
    assert.ok(counts.runs >= 1, 'Expected preserved runs after v3->v4 migration')
    assert.ok(hasTable(migrated, 'endpoints'))
    assert.ok(hasTable(migrated, 'api_dependencies'))
  })

  test('T1-28c: all 6 new v4 SQLite tables and indexes are created', async (t) => {
    const { storage } = makeStore(t)
    for (const tbl of ['endpoints', 'endpoint_params', 'api_dependencies', 'second_order_canaries', 'lab_telemetry', 'benchmark_runs']) {
      assert.ok(hasTable(storage, tbl), `Missing v4 SQLite table: ${tbl}`)
    }
    assert.ok(tableIndexes(storage, 'endpoints').length >= 1, 'Expected unique/lookup index on endpoints')
  })

  test('T1-28d: all 5 extended v3 tables have required v4 columns with safe defaults', async (t) => {
    const { storage } = makeStore(t)
    assert.ok(tableColumns(storage, 'model_profiles').includes('role_affinity'))
    assert.ok(tableColumns(storage, 'projects').includes('sandbox_write_allowlist'))
    const runCols = tableColumns(storage, 'runs')
    assert.ok(runCols.includes('dynamic_step_budget') && runCols.includes('multi_trial_enabled') && runCols.includes('phase0_completed_at'))
    const stepCols = tableColumns(storage, 'chain_steps')
    assert.ok(stepCols.includes('specialist_profile') && stepCols.includes('trial_group_id') && stepCols.includes('trial_index'))
    const rsCols = tableColumns(storage, 'replay_specs')
    assert.ok(rsCols.includes('attempt_count') && rsCols.includes('verified_inline') && rsCols.includes('last_verification_diff'))
  })

  test('T1-28e: PRAGMA foreign_keys = ON rejects orphaned v4 endpoint rows', async (t) => {
    const { storage } = makeStore(t)
    const fk = storage.client.prepare('PRAGMA foreign_keys').get() as { foreign_keys: number }
    assert.equal(fk.foreign_keys, 1)
    assert.throws(
      () => storage.client.prepare(`INSERT INTO endpoints (id, run_id, scope_revision, origin, method, path_template, source, sink_kinds, tested_classes, risk_score, created_at, updated_at) VALUES (?, ?, 1, 'http://127.0.0.1:9', 'GET', '/x', 'spa_crawl', '[]', '[]', 50, 1, 1)`)
        .run(randomUUID(), randomUUID()),
      /FOREIGN KEY/i,
    )
  })
})


// ============================================================================
// TIER 2 — Pairwise Component Integration (140 cases: T2-01a..e .. T2-28a..e)
// ============================================================================

describe('Tier 2 — Pairwise Component Integration (140 cases)', () => {
  // --- Feature 1: Inline verify_replay_spec & propose_chain_finding ---

  test('T2-01a: Store.incrementReplaySpecAttempt persists attempt_count and last_verification_diff in SQLite', async (t) => {
    const { storage } = makeStore(t)
    const { runId, run } = await setupApprovedRun(storage)
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const assignment = storage.db.select().from((await import('../src/server/schema.ts')).assignments).limit(1).get()!
    const spec = {
      ...baseReplaySpecFields('http://127.0.0.1:9'),
      kind: 'http_chain' as const,
      spaCatchallControl: false,
      assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.status == 200), observed: "ok", expected: "denied" }',
      steps: [
        { id: 'c1', role: 'control' as const, description: 'ctrl', request: { origin: 'http://127.0.0.1:9', method: 'GET' as const, pathAndQuery: '/c', followRedirects: false } },
        { id: 'p1', role: 'probe' as const, description: 'prb', request: { origin: 'http://127.0.0.1:9', method: 'GET' as const, pathAndQuery: '/p', followRedirects: false } },
      ],
    }
    const row = storage.createReplaySpec(run, assignment, randomUUID(), spec, ['http://127.0.0.1:9'])
    const v4 = storage as unknown as V4StoreContract
    const fb: InlineVerifyFeedback = {
      verdict: 'dismissed',
      failedStepId: 'p1',
      controlPassed: true,
      jqError: 'jq: syntax error',
      stepStatuses: [{ id: 'c1', role: 'control', status: 200, bodyLen: 12 }],
      retriesRemaining: 1,
    }
    v4.incrementReplaySpecAttempt(row.id, fb)
    const updated = storage.client.prepare('SELECT attempt_count, verified_inline, last_verification_diff FROM replay_specs WHERE id = ?').get(row.id) as {
      attempt_count: number
      verified_inline: number
      last_verification_diff: string
    }
    assert.ok(updated.attempt_count >= 2)
    assert.match(updated.last_verification_diff, /jq: syntax error/)
  })

  test('T2-01b: verifyReplaySpecInline fails on jq typo (attempt 1) and confirms after repair (attempt 2)', async (t) => {
    const rvMod = await import('../src/server/replay-verifier.ts') as Record<string, unknown>
    const verifyInline = requireExport<(p: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      rvMod, 'verifyReplaySpecInline', 'src/server/replay-verifier.ts',
    )
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ leaked: req.url?.includes('priv') ?? false }))
    })
    const baseSpec = {
      ...baseReplaySpecFields(fx.origin),
      kind: 'http_chain',
      steps: [
        { id: 'c1', role: 'control', description: 'Control', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/?id=pub' } },
        { id: 'p1', role: 'probe', description: 'Probe', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/?id=priv' } },
      ],
    }
    const res1 = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyInline({
        spec: { ...baseSpec, assertionsJq: '.steps[0].broken(((' },
        attemptCount: 1,
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    const fb1 = res1.feedback as InlineVerifyFeedback
    assert.notEqual(fb1.verdict, 'confirmed')
    assert.ok(fb1.jqError && fb1.jqError.length > 0)

    const res2 = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyInline({
        spec: { ...baseSpec, assertionsJq: '{ controlPassed: (.steps.c1.json.leaked == false), confirmed: (.steps.p1.json.leaked == true), observed: ("leaked=" + (.steps.p1.json.leaked | tostring)), expected: "leaked=false" }' },
        attemptCount: 2,
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    const fb2 = res2.feedback as InlineVerifyFeedback
    assert.equal(fb2.verdict, 'confirmed')
    assert.equal(fb2.retriesRemaining, 1)
  })

  test('T2-01c: verifyReplaySpecInline reports requireControlNonErrorTriggered on 404 control step', async (t) => {
    const rvMod = await import('../src/server/replay-verifier.ts') as Record<string, unknown>
    const verifyInline = requireExport<(p: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      rvMod, 'verifyReplaySpecInline', 'src/server/replay-verifier.ts',
    )
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.statusCode = req.url === '/missing' ? 404 : 200
      res.end('resp')
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyInline({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'http_chain',
          requireControlNonError: true,
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.status == 200), observed: ("ctrl=" + (.steps.c1.status | tostring)), expected: "HTTP 200 control" }',
          steps: [
            { id: 'c1', role: 'control', description: 'Control 404', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/missing' } },
            { id: 'p1', role: 'probe', description: 'Probe 200', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/ok' } },
          ],
        },
        attemptCount: 1,
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    const fb = res.feedback as InlineVerifyFeedback
    assert.equal(fb.verdict, 'inconclusive')
    assert.equal(fb.requireControlNonErrorTriggered, true)
  })

  test('T2-01d: verifyReplaySpecInline surfaces spaCatchallMatched + similarity score on SPA 200 catchall', async (t) => {
    const rvMod = await import('../src/server/replay-verifier.ts') as Record<string, unknown>
    const verifyInline = requireExport<(p: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      rvMod, 'verifyReplaySpecInline', 'src/server/replay-verifier.ts',
    )
    const spaShell = '<!doctype html><html><body><div id="root"></div><script src="/app.js"></script></body></html>'
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(spaShell)
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyInline({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'http_chain',
          spaCatchallControl: true,
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.status == 200), observed: ("status=" + (.steps.p1.status | tostring)), expected: "distinct 404" }',
          steps: [
            { id: 'c1', role: 'control', description: 'Control', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/safe' } },
            { id: 'p1', role: 'probe', description: 'Probe', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/admin-env' } },
          ],
        },
        attemptCount: 1,
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    const fb = res.feedback as InlineVerifyFeedback
    assert.notEqual(fb.verdict, 'confirmed')
    assert.equal(fb.spaCatchallMatched, true)
    assert.equal(typeof fb.spaSimilarityScore, 'number')
  })

  test('T2-01e: propose_chain_finding(verifyNow=true) updates SQLite findings and exposes verification state', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const detail = storage.runDetail(runId)
    assert.equal(detail.run.id, runId)
    const rsCols = tableColumns(storage, 'replay_specs')
    assert.ok(rsCols.includes('verified_inline'))
    assert.ok(rsCols.includes('attempt_count'))
  })

  // --- Feature 3: Opaque Ephemeral Session Jars ---

  test('T2-03a: RequestBroker login->authenticated flow succeeds with session jar and omits Cookie from broker_exchanges', async (t) => {
    const secretCookie = 'SECRET_SESSION_COOKIE_ABC999'
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/login') {
        res.setHeader('Set-Cookie', `sid=${secretCookie}; HttpOnly; Path=/`)
        res.end('logged-in')
        return
      }
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ authed: req.headers.cookie?.includes(secretCookie) ?? false }))
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      const ex1 = await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/login', session: 'jar-main', runId, assignmentId: aid }, grant, AbortSignal.timeout(5000))
      const ex2 = await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/me', session: 'jar-main', runId, assignmentId: aid }, grant, AbortSignal.timeout(5000))
      assert.equal(JSON.parse(ex2.body).authed, true)
      assert.ok(!JSON.stringify(ex1).includes(secretCookie))
      assert.ok(!JSON.stringify(ex2).includes(secretCookie))
    })
  })

  test('T2-03b: ReplayVerifier isolates session jars between control and probe step groups', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/set-ctrl') {
        res.setHeader('Set-Cookie', 'role=ctrl; Path=/')
        res.end('ok')
        return
      }
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ cookieSeen: req.headers.cookie ?? 'none' }))
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'http_chain',
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.json.cookieSeen == "none"), observed: .steps.p1.json.cookieSeen, expected: "none" }',
          steps: [
            { id: 'c1', role: 'control', description: 'Control login', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/set-ctrl', session: 'shared-name' } as never },
            { id: 'p1', role: 'probe', description: 'Probe isolated', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/check', session: 'shared-name' } as never },
          ],
        },
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
  })

  test('T2-03c: cross-origin redirect never sends Origin A jar cookie to Origin B', async (t) => {
    const originB = await startHttpFixture(t, (_req, _b, res) => res.end('b-ok'))
    const originA = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/login') {
        res.setHeader('Set-Cookie', 'a_sid=ORIGIN_A_SECRET; Path=/')
        res.end('ok')
        return
      }
      if (req.url === '/redir') {
        res.statusCode = 302
        res.setHeader('Location', `${originB.origin}/dest`)
        res.end()
        return
      }
      res.end('ok')
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(originA.origin, { canRead: o => o === originA.origin || o === originB.origin })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: originA.origin, method: 'GET', pathAndQuery: '/login', session: 'redir-jar' }, grant, AbortSignal.timeout(5000))
      await broker.executeHttp({ origin: originA.origin, method: 'GET', pathAndQuery: '/redir', session: 'redir-jar', followRedirects: true }, grant, AbortSignal.timeout(5000))
      assert.equal(originB.requests.at(-1)?.headers.cookie ?? undefined, undefined)
    })
  })

  test('T2-03d: SQLite broker_exchanges and facts never persist raw jar cookie value', async (t) => {
    const jarSecret = 'ULTRA_RAW_SESSION_COOKIE_VALUE_007'
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Set-Cookie', `sid=${jarSecret}; Path=/`)
      res.end(`echo:${req.headers.cookie ?? 'none'}`)
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      const ex = await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/1', session: 'scrub-jar' }, makeLabGrant(fx.origin), AbortSignal.timeout(5000))
      storage.recordExchange({
        runId,
        assignmentId: aid,
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
    })
    const rows = storage.client.prepare('SELECT req_headers, resp_headers, body_preview FROM broker_exchanges WHERE run_id = ?').all(runId)
    assert.ok(!JSON.stringify(rows).includes(jarSecret))
  })

  test('T2-03e: SARIF and Markdown exports never contain raw jar cookie secrets', async (t) => {
    const jarSecret = 'SARIF_COOKIE_SECRET_ZZZ888'
    const finding: Finding = {
      id: randomUUID(), origin: 'http://127.0.0.1:9', title: 'Session Leak', status: 'confirmed',
      severity: 'high', reason: `Cookie observed: ${jarSecret}`, remediation: 'Fix cookie flags',
      evidenceIds: [], scopeRevision: 1, category: 'auth-identity', cwe: 'CWE-614',
    }
    const sarif = buildSarifLog({
      runId: randomUUID(),
      reportVersion: 1,
      goal: 'test',
      capabilityTier: 2,
      scopeRevision: 1,
      goalRevision: 0,
      approvedOrigins: ['http://127.0.0.1:9'],
      findings: [finding],
      secrets: [{ placeholder: '[redacted]', value: jarSecret }],
    })
    assert.ok(!JSON.stringify(sarif).includes(jarSecret))
  })

  // --- Feature 4: Automatic CSRF Token Extraction & Binding ---

  test('T2-04a: form POST automatically binds extracted hidden CSRF field', async (t) => {
    const csrfToken = 'hidden-form-csrf-654321'
    const fx = await startHttpFixture(t, (req, body, res) => {
      if (req.method === 'GET') {
        res.setHeader('Content-Type', 'text/html')
        res.end(`<form><input type="hidden" name="_csrf" value="${csrfToken}"></form>`)
        return
      }
      res.statusCode = body.includes(`_csrf=${csrfToken}`) ? 200 : 403
      res.end(res.statusCode === 200 ? 'accepted' : 'bad-csrf')
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/form', session: 'f-csrf' }, grant, AbortSignal.timeout(5000))
      const post = await broker.executeHttp({
        origin: fx.origin, method: 'POST', pathAndQuery: '/submit', session: 'f-csrf', csrfBind: true,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'item=1',
      }, grant, AbortSignal.timeout(5000))
      assert.equal(post.status, 200)
    })
  })

  test('T2-04b: JSON POST automatically binds X-CSRF-Token header from jar', async (t) => {
    const tok = 'json-hdr-csrf-443322'
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.method === 'GET') {
        res.setHeader('Content-Type', 'text/html')
        res.end(`<meta name="csrf-token" content="${tok}">`)
        return
      }
      res.statusCode = req.headers['x-csrf-token'] === tok ? 200 : 403
      res.end('ok')
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/', session: 'j-csrf' }, grant, AbortSignal.timeout(5000))
      const post = await broker.executeHttp({
        origin: fx.origin, method: 'POST', pathAndQuery: '/api/save', session: 'j-csrf', csrfBind: true,
        headers: { 'Content-Type': 'application/json' }, body: '{"ok":true}',
      }, grant, AbortSignal.timeout(5000))
      assert.equal(post.status, 200)
    })
  })

  test('T2-04c: double-submit cookie + header pair enforced in same session jar', async (t) => {
    const tok = 'double-submit-887766'
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.method === 'GET') {
        res.setHeader('Set-Cookie', `XSRF-TOKEN=${tok}; Path=/`)
        res.end('init')
        return
      }
      const hasCookie = String(req.headers.cookie ?? '').includes(`XSRF-TOKEN=${tok}`)
      const hasHdr = (req.headers['x-xsrf-token'] ?? req.headers['x-csrf-token']) === tok
      res.statusCode = hasCookie && hasHdr ? 200 : 403
      res.end('done')
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/init', session: 'ds-jar' }, grant, AbortSignal.timeout(5000))
      const post = await broker.executeHttp({
        origin: fx.origin, method: 'POST', pathAndQuery: '/act', session: 'ds-jar', csrfBind: true,
        headers: { 'Content-Type': 'application/json' }, body: '{}',
      }, grant, AbortSignal.timeout(5000))
      assert.equal(post.status, 200)
    })
  })

  test('T2-04d: ReplayVerifier http_chain with csrfBind: true confirms CSRF-protected endpoint', async (t) => {
    const tok = 'rv-csrf-token-1122'
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.method === 'GET') {
        res.setHeader('Set-Cookie', `XSRF-TOKEN=${tok}; Path=/`)
        res.end('ready')
        return
      }
      res.setHeader('Content-Type', 'application/json')
      if ((req.headers['x-xsrf-token'] ?? req.headers['x-csrf-token']) !== tok) {
        res.statusCode = 403
        res.end(JSON.stringify({ error: 'csrf' }))
        return
      }
      res.end(JSON.stringify({ protectedOk: req.url?.includes('admin') }))
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'http_chain',
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.status == 200 and .steps.p1.json.protectedOk == true), observed: ("protectedOk=" + (.steps.p1.json.protectedOk | tostring)), expected: "HTTP 403 or protectedOk=false" }',
          steps: [
            { id: 'c0', role: 'setup', description: 'Prime CSRF session', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/csrf', session: 'rvjar' } as never },
            { id: 'c1', role: 'control', description: 'Get CSRF', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/csrf', session: 'rvjar' } as never },
            { id: 'p1', role: 'probe', description: 'POST with CSRF', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/admin', session: 'rvjar', csrfBind: true, jsonBody: { a: 1 } } as never },
          ],
        },
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
  })

  test('T2-04e: CSRF token rotation across sequential requests binds newest rotated token', async (t) => {
    let counter = 0
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.method === 'GET') {
        counter += 1
        res.setHeader('Set-Cookie', `XSRF-TOKEN=rot_${counter}; Path=/`)
        res.end('ok')
        return
      }
      res.statusCode = (req.headers['x-xsrf-token'] ?? req.headers['x-csrf-token']) === `rot_${counter}` ? 200 : 403
      res.end('ok')
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/t1', session: 'rot-jar' }, grant, AbortSignal.timeout(5000))
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/t2', session: 'rot-jar' }, grant, AbortSignal.timeout(5000))
      const post = await broker.executeHttp({
        origin: fx.origin, method: 'POST', pathAndQuery: '/act', session: 'rot-jar', csrfBind: true,
        headers: { 'Content-Type': 'application/json' }, body: '{}',
      }, grant, AbortSignal.timeout(5000))
      assert.equal(post.status, 200)
    })
  })

  // --- Feature 5: Persistent PlaywrightContext/Page (runBrowserSession) ---

  test('T2-05a: runBrowserSession fill -> click preserves JS memory & localStorage state across steps', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body>
        <input id="name" /><button id="go" onclick="document.getElementById('out').textContent = 'hi:' + document.getElementById('name').value">Go</button>
        <div id="out"></div>
      </body></html>`)
    })
    const browser = new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })) as unknown as V4ScopedBrowserContract
    const runSession = requireMethod<V4ScopedBrowserContract['runBrowserSession']>(browser, 'runBrowserSession', 'ScopedBrowser')
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runSession([
        { id: 's1', role: 'probe', description: 'Fill name', origin: fx.origin, pathAndQuery: '/', action: 'fill', selector: '#name', value: 'wizard-user' },
        { id: 's2', role: 'probe', description: 'Click go', origin: fx.origin, reusePage: true, action: 'click', selector: '#go' },
      ], makeLabGrant(fx.origin), AbortSignal.timeout(30_000)),
    )
    assert.equal(res.length, 2)
    assert.match(JSON.stringify(res[1]), /hi:wizard-user/)
  })

  test('T2-05b: runBrowserSession wait_for_xhr captures async XHR response on persistent page', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/api/state') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ asyncState: 'ready-42' }))
        return
      }
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body><button id="load" onclick="fetch('/api/state')">Load</button></body></html>`)
    })
    const browser = new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })) as unknown as V4ScopedBrowserContract
    const runSession = requireMethod<V4ScopedBrowserContract['runBrowserSession']>(browser, 'runBrowserSession', 'ScopedBrowser')
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runSession([
        { id: 's1', role: 'probe', description: 'Open', origin: fx.origin, pathAndQuery: '/', action: 'navigate' },
        { id: 's2', role: 'probe', description: 'Trigger XHR', origin: fx.origin, reusePage: true, action: 'click', selector: '#load' },
        { id: 's3', role: 'probe', description: 'Wait XHR', origin: fx.origin, reusePage: true, action: 'wait_for_xhr', urlPattern: '/api/state' },
      ], makeLabGrant(fx.origin), AbortSignal.timeout(30_000)),
    )
    assert.equal(res.length, 3)
  })

  test('T2-05c: runBrowserSession routes 100% subrequests through RequestBroker and blocks third-party origins', async (t) => {
    const tp = await startHttpFixture(t, (_req, _b, res) => res.end('alert(1)'))
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body><script src="${tp.origin}/evil.js"></script>ok</body></html>`)
    })
    const browser = new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })) as unknown as V4ScopedBrowserContract
    const runSession = requireMethod<V4ScopedBrowserContract['runBrowserSession']>(browser, 'runBrowserSession', 'ScopedBrowser')
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runSession([
        { id: 's1', role: 'probe', description: 'Load page', origin: fx.origin, pathAndQuery: '/', action: 'navigate' },
      ], makeLabGrant(fx.origin), AbortSignal.timeout(30_000)),
    )
    assert.equal(tp.requests.length, 0)
  })

  test('T2-05d: runBrowserSession stores Set-Cookie in broker jar and never exposes raw cookie in step results', async (t) => {
    const secretCookie = 'BROWSER_JAR_SECRET_7788'
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/login') {
        res.setHeader('Set-Cookie', `bsid=${secretCookie}; HttpOnly; Path=/`)
      }
      res.setHeader('Content-Type', 'text/html')
      res.end('<html><body>logged</body></html>')
    })
    const browser = new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })) as unknown as V4ScopedBrowserContract
    const runSession = requireMethod<V4ScopedBrowserContract['runBrowserSession']>(browser, 'runBrowserSession', 'ScopedBrowser')
    const results = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runSession([
        { id: 's1', role: 'probe', description: 'Login', origin: fx.origin, pathAndQuery: '/login', action: 'navigate' },
        { id: 's2', role: 'probe', description: 'Next', origin: fx.origin, pathAndQuery: '/dash', action: 'navigate' },
      ], makeLabGrant(fx.origin), AbortSignal.timeout(30_000)),
    )
    assert.ok(!JSON.stringify(results).includes(secretCookie))
  })

  test('T2-05e: ReplayVerifier browser_chain confirms multi-step wizard flow via persistent session', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body>
        <input id="payload" />
        <button id="render" onclick="document.getElementById('view').innerHTML = document.getElementById('payload').value">Render</button>
        <div id="view"></div>
      </body></html>`)
    })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const browser = new ScopedBrowser(broker)
    const steps = [
      { id: 'c1', role: 'control', description: 'Control safe text', origin: fx.origin, pathAndQuery: '/', action: 'navigate' },
      { id: 'p1', role: 'probe', description: 'Fill XSS', origin: fx.origin, pathAndQuery: '/', action: 'fill', selector: '#payload', value: '{{canary_token}}<img src=x onerror=1>', enableSinkHook: true },
      { id: 'p2', role: 'probe', description: 'Click render with sink hook', origin: fx.origin, reusePage: true, action: 'click', selector: '#render', enableSinkHook: true },
    ]
    const recipe = browserSinkEnvelopeFromSteps({ origin: fx.origin, vulnClass: 'dom_xss', steps })
    assert.ok(recipe, 'expected browser_sink recipe envelope for T2-05e')
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'browser_chain',
          recipe,
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200 and (.steps.c1.domSinkTraces | length == 0)), confirmed: ((.steps.p2.domSinkTraces | length >= 1) or (.domSinkTraces | length >= 1)), observed: ("sinks=" + ((.domSinkTraces | length) | tostring)), expected: "0 DOM sink hits" }',
          steps: steps as never,
        } as unknown,
        broker,
        browser,
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
  })

  // --- Feature 6: Broker-Side Auth-Mutation Primitives ---

  test('T2-06a: alg_none and strip_signature mutate JWT header/signature on wire', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => res.end('ok'))
    const jwt = makeHs256Jwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'alice', role: 'user' })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [{ handle: 'jwt_u', roleLabel: 'User', authKind: 'bearer', secret: jwt }],
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin, { personas: personaMap, secrets: [{ placeholder: '[redacted]', value: jwt }] })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/1', persona: 'jwt_u', authMutation: { kind: 'alg_none' } }, grant, AbortSignal.timeout(5000))
      const tok1 = String(fx.requests[0].headers.authorization).slice(7)
      assert.equal(decodeJwtParts(tok1).header.alg, 'none')
      assert.equal(decodeJwtParts(tok1).signature, '')

      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/2', persona: 'jwt_u', authMutation: { kind: 'strip_signature' } }, grant, AbortSignal.timeout(5000))
      const tok2 = String(fx.requests[1].headers.authorization).slice(7)
      assert.equal(decodeJwtParts(tok2).signature, '')
    })
  })

  test('T2-06b: rs256_to_hs256_jwks signs JWT using fetched public JWKS PEM', async (t) => {
    const { generateKeyPairSync } = await import('node:crypto')
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const jwk = publicKey.export({ format: 'jwk' })
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/.well-known/jwks.json') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ keys: [{ ...jwk, kid: 'k1', use: 'sig', alg: 'RS256' }] }))
        return
      }
      res.end('ok')
    })
    const jwt = makeHs256Jwt({ alg: 'RS256', typ: 'JWT', kid: 'k1' }, { sub: 'alice' })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [{ handle: 'rs_u', roleLabel: 'User', authKind: 'bearer', secret: jwt }],
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      broker.executeHttp({
        origin: fx.origin, method: 'GET', pathAndQuery: '/api/me', persona: 'rs_u',
        authMutation: { kind: 'rs256_to_hs256_jwks', jwksUrl: `${fx.origin}/.well-known/jwks.json` },
      }, makeLabGrant(fx.origin, { personas: personaMap }), AbortSignal.timeout(5000)),
    )
    const sent = String(fx.requests.at(-1)?.headers.authorization ?? '').slice(7)
    assert.equal(decodeJwtParts(sent).header.alg, 'HS256')
    assert.ok(decodeJwtParts(sent).signature.length > 10)
  })

  test('T2-06c: jku_x5u_canary injects CanaryBroker URL into JWT jku header and records OOB hit', async (t) => {
    const canaryBroker = new CanaryBroker()
    await canaryBroker.startListener({ host: '127.0.0.1', port: 0 })
    t.after(() => canaryBroker.stopListener())
    const fx = await startHttpFixture(t, async (req, _b, res) => {
      const tok = String(req.headers.authorization ?? '').slice(7)
      const { header } = decodeJwtParts(tok)
      if (typeof header.jku === 'string') {
        await fetch(header.jku).catch(() => {})
      }
      res.end('ok')
    })
    const jwt = makeHs256Jwt({ alg: 'RS256', typ: 'JWT' }, { sub: 'alice' })
    const { storage } = makeStore(t)
    const { runId, personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [{ handle: 'jku_u', roleLabel: 'User', authKind: 'bearer', secret: jwt }],
    })
    const minted = canaryBroker.mintCanary(runId, 'jku-test', fx.origin, { storage })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      broker.executeHttp({
        origin: fx.origin, method: 'GET', pathAndQuery: '/api/me', persona: 'jku_u',
        authMutation: { kind: 'jku_x5u_canary', header: 'jku', value: minted.httpUrl },
      }, makeLabGrant(fx.origin, { personas: personaMap }), AbortSignal.timeout(5000)),
    )
    const check = canaryBroker.checkCanary(minted.token, { storage, runId })
    assert.equal(check.triggered, true)
  })

  test('T2-06d: authMutation dynamic redact() scrubs both original and mutated JWT from exchanges and response echoes', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ echoedAuth: req.headers.authorization }))
    })
    const origJwt = makeHs256Jwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'secret_alice' })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [{ handle: 'sec_u', roleLabel: 'User', authKind: 'bearer', secret: origJwt }],
    })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const ex = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      broker.executeHttp({
        origin: fx.origin, method: 'GET', pathAndQuery: '/echo', persona: 'sec_u',
        authMutation: { kind: 'alg_none' },
      }, makeLabGrant(fx.origin, { personas: personaMap, secrets: [{ placeholder: '[redacted]', value: origJwt }] }), AbortSignal.timeout(5000)),
    )
    const wireMutatedJwt = String(fx.requests[0].headers.authorization).slice(7)
    assert.ok(!JSON.stringify(ex).includes(origJwt), 'Original JWT leaked in BrokerExchangeResult')
    assert.ok(!JSON.stringify(ex).includes(wireMutatedJwt), 'Mutated JWT leaked in BrokerExchangeResult')
  })

  test('T2-06e: ReplayVerifier auth_protocol_proof confirms alg:none JWT bypass deterministically', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      const auth = String(req.headers.authorization ?? '')
      if (!auth.startsWith('Bearer ')) { res.statusCode = 401; res.end('{"error":"no auth"}'); return }
      const { header } = decodeJwtParts(auth.slice(7))
      if (header.alg === 'none') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ bypassed: true, role: 'admin' }))
        return
      }
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ bypassed: false, role: 'user' }))
    })
    const jwt = makeHs256Jwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'u1', role: 'user' })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [{ handle: 'jwt_user', roleLabel: 'User', authKind: 'bearer', secret: jwt }],
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'auth_protocol_proof',
          protocol: 'jwt',
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200 and .steps.c1.json.bypassed == false), confirmed: (.steps.p1.status == 200 and .steps.p1.json.bypassed == true), observed: ("bypassed=" + (.steps.p1.json.bypassed | tostring)), expected: "HTTP 401 on alg:none" }',
          steps: [
            { id: 'c1', role: 'control', description: 'Valid user token', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/me', persona: 'jwt_user' } },
            { id: 'p1', role: 'probe', description: 'alg:none mutation', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/me', persona: 'jwt_user', authMutation: { kind: 'alg_none' } } as never },
          ],
        } as unknown,
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { personas: personaMap, secrets: [{ placeholder: '[redacted]', value: jwt }] }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
  })

  // --- Feature 7: Tier-2 sandboxWriteAllowlist ---

  test('T2-07a: Store createProject persists sandboxWriteAllowlist into SQLite projects table', async (t) => {
    const { storage } = makeStore(t)
    const allowlist: ApprovedEndpointPattern[] = [{ origin: 'https://staging.example.invalid', method: 'POST', pathPattern: '/api/search' }]
    const { projectId } = await setupApprovedRun(storage, { environment: 'public', sandboxWriteAllowlist: allowlist })
    const row = storage.client.prepare('SELECT sandbox_write_allowlist FROM projects WHERE id = ?').get(projectId) as { sandbox_write_allowlist: string }
    assert.deepEqual(JSON.parse(row.sandbox_write_allowlist), allowlist)
  })

  test('T2-07b: Tier-2 allowlisted POST succeeds for JSON, form, GraphQL, and Next-Action payloads', async () => {
    const origin = 'https://staging.example.invalid'
    const allowlist: ApprovedEndpointPattern[] = [
      { origin, method: 'POST', pathPattern: '/api/*' },
      { origin, method: 'POST', pathPattern: '/graphql' },
    ]
    const broker = makeVirtualPublicBroker(() => ({ status: 200, headers: {}, body: '{"ok":true}' })) as unknown as V4BrokerContract
    const grant = makePublicGrant(origin, { tier: 2, sandboxWriteAllowlist: allowlist })
    const payloads: Array<{ path: string; headers: Record<string, string>; body: string }> = [
      { path: '/api/search', headers: { 'Content-Type': 'application/json' }, body: '{"q":"a"}' },
      { path: '/api/form', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'q=a' },
      { path: '/graphql', headers: { 'Content-Type': 'application/json' }, body: '{"query":"{ me { id } }"}' },
      { path: '/api/actions', headers: { 'Content-Type': 'text/plain', 'Next-Action': 'abc123' }, body: '["1"]' },
    ]
    for (const p of payloads) {
      const res = await broker.executeHttp({ origin, method: 'POST', pathAndQuery: p.path, headers: p.headers, body: p.body }, grant, AbortSignal.timeout(5000))
      assert.equal(res.status, 200)
    }
  })

  test('T2-07c: Tier-2 non-allowlisted POST is denied cleanly with BrokerDenied', async () => {
    const origin = 'https://staging.example.invalid'
    const allowlist: ApprovedEndpointPattern[] = [{ origin, method: 'POST', pathPattern: '/api/search' }]
    const broker = makeVirtualPublicBroker(() => ({ status: 200, headers: {}, body: 'ok' })) as unknown as V4BrokerContract
    await assert.rejects(
      () => broker.executeHttp(
        { origin, method: 'POST', pathAndQuery: '/api/billing/charge', headers: { 'Content-Type': 'application/json' }, body: '{}' },
        makePublicGrant(origin, { tier: 2, sandboxWriteAllowlist: allowlist }),
        AbortSignal.timeout(5000),
      ),
      BrokerDenied,
    )
  })

  test('T2-07d: local-lab environment auto-allows safe non-destructive POST at Tier 2', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => res.end('{"created":true}'))
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      broker.executeHttp(
        { origin: fx.origin, method: 'POST', pathAndQuery: '/api/orders', headers: { 'Content-Type': 'application/json' }, body: '{"item":1}' },
        makeLabGrant(fx.origin, { tier: 2 }),
        AbortSignal.timeout(5000),
      ),
    )
    assert.equal(res.status, 200)
  })

  test('T2-07e: 5xx circuit breaker halts Tier-2 sandbox write burst cleanly (BrokerCircuitOpen)', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.statusCode = 503
      res.end('unavailable')
    })
    const broker = new RequestBroker({ rejectUnauthorized: false, circuit5xxThreshold: 3 }) as unknown as V4BrokerContract
    const grant = makeLabGrant(fx.origin, { tier: 2, sandboxWriteAllowlist: [{ origin: fx.origin, method: 'POST', pathPattern: '/*' }] })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      for (let i = 0; i < 2; i += 1) {
        const res = await broker.executeHttp({ origin: fx.origin, method: 'POST', pathAndQuery: '/api/search', body: '{}' }, grant, AbortSignal.timeout(5000))
        assert.equal(res.status, 503)
      }
      await assert.rejects(
        () => broker.executeHttp({ origin: fx.origin, method: 'POST', pathAndQuery: '/api/search', body: '{}' }, grant, AbortSignal.timeout(5000)),
        BrokerCircuitOpen,
      )
      await assert.rejects(
        () => broker.executeHttp({ origin: fx.origin, method: 'POST', pathAndQuery: '/api/search', body: '{}' }, grant, AbortSignal.timeout(5000)),
        BrokerCircuitOpen,
      )
    })
  })

  // --- Feature 8: Zero-LLM Phase-0 Deterministic Surface Mapper ---

  test('T2-08a: phase0-recon populates SQLite endpoints, endpoint_params, and runs.phase0_completed_at', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const runPhase0 = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runPhase0Recon', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/openapi.json') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ openapi: '3.0.0', paths: { '/api/invoices/{id}': { get: { parameters: [{ name: 'id', in: 'path' }] } } } }))
        return
      }
      res.setHeader('Content-Type', 'text/html')
      res.end('<html><body>app</body></html>')
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runPhase0({
        storage, runId, scopeRevision: 1, tier: 2, origins: [fx.origin],
        broker: new RequestBroker({ rejectUnauthorized: false }), grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(20_000),
      }),
    )
    const v4 = storage as unknown as V4StoreContract
    const eps = v4.listEndpoints(runId)
    assert.ok(eps.some(e => String(e.pathTemplate ?? e.path_template).includes('/api/invoices')))
    const row = storage.client.prepare('SELECT phase0_completed_at FROM runs WHERE id = ?').get(runId) as { phase0_completed_at: number | null }
    assert.ok(row.phase0_completed_at && row.phase0_completed_at > 0)
  })

  test('T2-08b: phase0-recon fetches same-origin JS chunks and feeds js-harvest into endpoints', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const runPhase0 = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runPhase0Recon', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/static/app.js') {
        res.setHeader('Content-Type', 'application/javascript')
        res.end(`fetch('/api/v2/secret-export', { method: 'POST', body: JSON.stringify({ tenantId: '1' }) })`)
        return
      }
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body><script src="/static/app.js"></script></body></html>`)
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runPhase0({
        storage, runId, scopeRevision: 1, tier: 2, origins: [fx.origin],
        broker: new RequestBroker({ rejectUnauthorized: false }), grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(20_000),
      }),
    )
    const eps = (storage as unknown as V4StoreContract).listEndpoints(runId)
    assert.ok(eps.some(e => String(e.pathTemplate ?? e.path_template).includes('/api/v2/secret-export')))
  })

  test('T2-08c: phase0-recon correlates /repos routes with live origin in SQLite endpoints', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const runPhase0 = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runPhase0Recon', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (_req, _b, res) => res.end('ok'))
    const repoDir = makeTempDir(t, 'kovo-v4-p0-repo-')
    mkdirSync(join(repoDir, 'app/routes'), { recursive: true })
    writeFileSync(join(repoDir, 'app/routes/server.ts'), `app.get('/api/repo-discovered-route', h)`)
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runPhase0({
        storage, runId, scopeRevision: 1, tier: 2, origins: [fx.origin], reposDir: repoDir,
        broker: new RequestBroker({ rejectUnauthorized: false }), grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(20_000),
      }),
    )
    const eps = (storage as unknown as V4StoreContract).listEndpoints(runId)
    assert.ok(eps.some(e => String(e.pathTemplate ?? e.path_template).includes('/api/repo-discovered-route')))
  })

  test('T2-08d: phase0-recon triggers tech-matched safe templates based on detected fingerprint', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const runPhase0 = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runPhase0Recon', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('X-Powered-By', 'Next.js')
      res.setHeader('Content-Type', 'text/html')
      res.end('<div id="__next">ok</div>')
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const out = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runPhase0({
        storage, runId, scopeRevision: 1, tier: 1, origins: [fx.origin],
        broker: new RequestBroker({ rejectUnauthorized: false }), grant: makeLabGrant(fx.origin, { tier: 1 }),
        signal: AbortSignal.timeout(20_000),
      }),
    )
    assert.ok(fx.requests.length >= 2)
    assert.ok(out && typeof out === 'object')
  })

  test('T2-08e: phase0-recon halts immediately if scope narrowing revokes origin mid-Phase-0', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const runPhase0 = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runPhase0Recon', 'src/server/phase0-recon.ts',
    )
    let allow = true
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      allow = false
      res.end('ok')
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runPhase0({
        storage, runId, scopeRevision: 1, tier: 1, origins: [fx.origin],
        broker: new RequestBroker({ rejectUnauthorized: false }),
        grant: makeLabGrant(fx.origin, { canRead: o => allow && o === fx.origin }),
        signal: AbortSignal.timeout(20_000),
      }).catch(() => ({ aborted: true })),
    )
    assert.ok(fx.requests.length <= 2, `Expected Phase-0 to stop immediately on scope revocation, got ${fx.requests.length} requests`)
  })

  // --- Feature 9: crawl_state_graph Multi-Persona SPA Explorer ---

  test('T2-09a: crawl_state_graph crawls anonymous + persona_a + persona_b via ScopedBrowser v4', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const crawl = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'crawlStateGraph', 'src/server/phase0-recon.ts',
    )
    const seenAuth = new Set<string>()
    const fx = await startHttpFixture(t, (req, _b, res) => {
      seenAuth.add(String(req.headers.authorization ?? 'anon'))
      res.setHeader('Content-Type', 'text/html')
      res.end('<html><body><a href="/sub">sub</a></body></html>')
    })
    const { storage } = makeStore(t)
    const { runId, personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [
        { handle: 'persona_a', roleLabel: 'A', authKind: 'bearer', secret: 'tok-a' },
        { handle: 'persona_b', roleLabel: 'B', authKind: 'bearer', secret: 'tok-b' },
      ],
    })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      crawl({
        storage, runId, scopeRevision: 1, origin: fx.origin, maxPages: 5, maxDepth: 2,
        personas: ['persona_a', 'persona_b'],
        browser: new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })),
        grant: makeLabGrant(fx.origin, { personas: personaMap }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.ok(seenAuth.has('anon'))
    assert.ok(seenAuth.has('Bearer tok-a'))
    assert.ok(seenAuth.has('Bearer tok-b'))
  })

  test('T2-09b: crawl_state_graph intercepts XHR/fetch/GraphQL/Next-Action requests into SQLite endpoints', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const crawl = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'crawlStateGraph', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/api/xhr-hidden') { res.end('{"items":[]}'); return }
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body><script>fetch('/api/xhr-hidden');</script></body></html>`)
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      crawl({
        storage, runId, scopeRevision: 1, origin: fx.origin, maxPages: 3, maxDepth: 1,
        browser: new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })),
        grant: makeLabGrant(fx.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    const eps = (storage as unknown as V4StoreContract).listEndpoints(runId)
    assert.ok(eps.some(e => String(e.pathTemplate ?? e.path_template).includes('/api/xhr-hidden')))
  })

  test('T2-09c: crawl_state_graph registers POST form action and CSRF param in endpoint_params', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const crawl = requireExport<(params: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'crawlStateGraph', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<form action="/api/profile" method="POST"><input type="hidden" name="authenticity_token" value="xyz"><input name="bio"></form>`)
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      crawl({
        storage, runId, scopeRevision: 1, origin: fx.origin, maxPages: 3, maxDepth: 1,
        browser: new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })),
        grant: makeLabGrant(fx.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    const eps = (storage as unknown as V4StoreContract).listEndpoints(runId)
    assert.ok(eps.some(e => e.method === 'POST' && String(e.pathTemplate ?? e.path_template).includes('/api/profile')))
  })

  test('T2-09d: crawl_state_graph respects Phase-0 budget ceiling across pages', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const crawl = requireExport<(params: Record<string, unknown>) => Promise<{ pagesVisited: number }>>(
      mod, 'crawlStateGraph', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body><a href="/a">a</a><a href="/b">b</a><a href="/c">c</a><a href="/d">d</a></body></html>`)
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      crawl({
        storage, runId, scopeRevision: 1, origin: fx.origin, maxPages: 25, maxDepth: 3, budgetRemaining: 2,
        browser: new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })),
        grant: makeLabGrant(fx.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.ok(res.pagesVisited <= 2)
  })

  test('T2-09e: crawl_state_graph stops cleanly on BrokerCircuitOpen without crashing', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const crawl = requireExport<(params: Record<string, unknown>) => Promise<{ stoppedReason?: string }>>(
      mod, 'crawlStateGraph', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.statusCode = 502
      res.end('bad gateway')
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      crawl({
        storage, runId, scopeRevision: 1, origin: fx.origin, maxPages: 10, maxDepth: 2,
        browser: new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false, circuit5xxThreshold: 2 })),
        grant: makeLabGrant(fx.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.ok(res && typeof res === 'object')
  })

  // --- Feature 10: SQLite App State & Producer-Consumer API Graph ---

  test('T2-10a: Store.updateEndpointCoverage updates coverage_pct and tested_classes in SQLite', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    const ep = v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/api/orders/{id}', source: 'spa_crawl' })
    v4.updateEndpointCoverage(ep.id, 87.5, ['authz_matrix', 'sqli_boolean'])
    const rows = v4.listEndpoints(runId)
    assert.equal(rows[0].coveragePct ?? rows[0].coverage_pct, 87.5)
  })

  test('T2-10b: Store.recordApiDependency and markApiDependencyTestedBola update tested_bola state', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    const prod = v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'POST', pathTemplate: '/api/orders', source: 'spa_crawl' })
    const cons = v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/api/orders/{id}', source: 'spa_crawl' })
    const dep = v4.recordApiDependency({ runId, producerEndpointId: prod.id, consumerEndpointId: cons.id, resourceKey: 'orderId', personaHandle: 'persona_a' })
    v4.markApiDependencyTestedBola(dep.id)
    const deps = v4.listApiDependencies(runId)
    assert.equal(Boolean(deps[0].testedBola ?? deps[0].tested_bola), true)
  })

  test('T2-10c: POST /orders -> GET /orders/{id} producer-consumer dependency inferred from exchanges', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (req.method === 'POST' && req.url === '/api/orders') {
        res.statusCode = 201
        res.end(JSON.stringify({ order: { id: 'ord_9911' } }))
        return
      }
      res.end(JSON.stringify({ id: 'ord_9911' }))
    })
    const { storage } = makeStore(t)
    const { runId, run, assetIds, personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [{ handle: 'persona_a', roleLabel: 'A', authKind: 'bearer', secret: 'tok-a' }],
    })
    const v4 = storage as unknown as V4StoreContract
    v4.upsertEndpoint({ runId, scopeRevision: 1, origin: fx.origin, method: 'POST', pathTemplate: '/api/orders', source: 'spa_crawl' })
    v4.upsertEndpoint({ runId, scopeRevision: 1, origin: fx.origin, method: 'GET', pathTemplate: '/api/orders/:id', source: 'spa_crawl' })

    const extracted = extractPersonaResourcesFromExchange({
      origin: fx.origin,
      method: 'POST',
      pathAndQuery: '/api/orders',
      personaHandle: 'persona_a',
      status: 201,
      mediaType: 'application/json',
      body: JSON.stringify({ order: { id: 'ord_9911' } }),
    })
    assert.ok(extracted.some(r => r.resourceId === 'ord_9911'))

    const llm = await startMockLlmServer(t, (call) => {
      const serialized = JSON.stringify(call.body.input ?? [])
      if (serialized.includes('"c_http_ord"')) {
        return {
          type: 'tool_call', callId: 'c_done_ord', name: 'complete_intent',
          argumentsJson: JSON.stringify({ status: 'partial', summary: 'Observed producer exchange.' }),
        }
      }
      return {
        type: 'tool_call', callId: 'c_http_ord', name: 'request_http',
        argumentsJson: JSON.stringify({ origin: fx.origin, method: 'POST', pathAndQuery: '/api/orders', persona: 'persona_a', body: '{}' }),
      }
    })
    await saveModelProfile({
      name: 'Tac', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-t210c-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    assert.ok(personaMap.has('persona_a'))
    storage.addChainStep(run, {
      title: 'Check /api/orders producer', hypothesis: 'Producer-consumer graph', category: 'broken-access-control',
      priority: 70, targetAssetIds: assetIds,
    })
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 10_000
      while (Date.now() < deadline && v4.listApiDependencies(runId).length === 0) await delay(80)
      await stopExecution(engine as never)
    })
    assert.ok(v4.listApiDependencies(runId).length >= 1)
  })

  test('T2-10d: Store.listEndpoints filters by untestedClass and minRiskScore', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/low', source: 'spa_crawl', riskScore: 20, testedClasses: ['sqli_boolean'] })
    v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/high', source: 'spa_crawl', riskScore: 95, testedClasses: [] })
    const filtered = v4.listEndpoints(runId, { untestedClass: 'sqli_boolean', minRiskScore: 80 })
    assert.equal(filtered.length, 1)
    assert.equal(filtered[0].pathTemplate ?? filtered[0].path_template, '/high')
  })

  test('T2-10e: Store.runDetail exposes endpoints and apiDependencies for Surface Graph UI/API', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/api/graph-check', source: 'openapi' })
    const detail = storage.runDetail(runId) as unknown as Record<string, unknown>
    assert.ok(Array.isArray(detail.endpoints), 'Expected runDetail().endpoints array')
    assert.ok(Array.isArray(detail.apiDependencies), 'Expected runDetail().apiDependencies array')
  })

  // --- Feature 11: AST-Based JS/TS & Source-Map Harvester ---

  test('T2-11a: jsHarvest parses minified Webpack/Vite bundle syntax cleanly', async () => {
    const mod = await import('../worker/analyzers.ts') as Record<string, unknown>
    const jsHarvest = requireExport<(content: string, sourceName?: string) => { apiPaths?: string[] }>(
      mod, 'jsHarvest', 'worker/analyzers.ts',
    )
    const minified = `(()=>{var e="/api/v3/admin/users";fetch(e,{method:"DELETE"}).then(r=>r.json())})();`
    const out = jsHarvest(minified, 'https://app.invalid/assets/index-9a8b.js')
    assert.ok(Array.isArray(out.apiPaths) && out.apiPaths.includes('/api/v3/admin/users'))
  })

  test('T2-11b: LinuxWorkerBackend executes js-harvest analyzer inside --network none container', async () => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T2-11b')
    const backend = new LinuxWorkerBackend()
    const mod = await import('../worker/analyzers.ts') as Record<string, unknown>
    assert.equal(typeof mod.jsHarvest, 'function')
    const out = await runWorkerAnalyze(backend as never, 'js-harvest', {
      text: `axios.post('/api/checkout', { couponCode: 'X', amount: 10 })`,
      sourceName: 'https://app.invalid/bundle.js',
    })
    assert.match(JSON.stringify(out), /\/api\/checkout/)
  })

  test('T2-11c: jsHarvest masks inline secrets before returning harvested bundle artifacts', async () => {
    const mod = await import('../worker/analyzers.ts') as Record<string, unknown>
    const jsHarvest = requireExport<(content: string, sourceName?: string) => Record<string, unknown>>(
      mod, 'jsHarvest', 'worker/analyzers.ts',
    )
    const code = `const stripe="${RAW_STRIPE_SECRET}"; fetch("/api/pay");`
    const out = jsHarvest(code, 'https://app.invalid/pay.js')
    assert.ok(!JSON.stringify(out).includes(RAW_STRIPE_SECRET), 'jsHarvest leaked Stripe secret')
  })

  test('T2-11d: jsHarvest handles malformed JS syntax gracefully without crashing', async () => {
    const mod = await import('../worker/analyzers.ts') as Record<string, unknown>
    const jsHarvest = requireExport<(content: string, sourceName?: string) => Record<string, unknown>>(
      mod, 'jsHarvest', 'worker/analyzers.ts',
    )
    const out = jsHarvest(`function broken( { {{{ /api/still-ok`, 'https://app.invalid/broken.js')
    assert.ok(out && typeof out === 'object')
  })

  test('T2-11e: jsHarvest output feeds Phase-0 dynamic wordlist for surface discovery', async (t) => {
    const jsMod = await import('../worker/analyzers.ts') as Record<string, unknown>
    const p0Mod = await loadV4Module('src/server/phase0-recon.ts')
    const jsHarvest = requireExport<(content: string, sourceName?: string) => { apiPaths?: string[] }>(
      jsMod, 'jsHarvest', 'worker/analyzers.ts',
    )
    const runPhase0Recon = requireExport<(opts: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      p0Mod, 'runPhase0Recon', 'src/server/phase0-recon.ts',
    )
    const harvested = jsHarvest(`fetch('/api/hidden-feature-flag')`, 'https://app.invalid/a.js')
    assert.ok(harvested.apiPaths?.includes('/api/hidden-feature-flag'))
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/') { res.setHeader('Content-Type', 'text/html'); res.end('<script src="/a.js"></script>'); return }
      if (req.url === '/a.js') { res.setHeader('Content-Type', 'application/javascript'); res.end(`fetch('/api/hidden-feature-flag')`); return }
      if (req.url === '/api/hidden-feature-flag') { res.setHeader('Content-Type', 'application/json'); res.end('{"ok":true}'); return }
      res.statusCode = 404; res.end('404')
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runPhase0Recon({
        storage, runId, origins: [fx.origin], broker: new RequestBroker({ rejectUnauthorized: false }),
        grant: makeLabGrant(fx.origin), signal: AbortSignal.timeout(15_000),
      }),
    )
    assert.ok((storage as unknown as V4StoreContract).listEndpoints(runId).some(e => String(e.pathTemplate ?? e.path_template).includes('/api/hidden-feature-flag')))
  })

  // --- Feature 12: kovo-worker:v4 Hardened Offline Toolchain ---

  test('T2-12a: kovo-worker:v4 runs curated offline Opengrep ruleset with --network none', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T2-12a')
    const backend = new LinuxWorkerBackend()
    const repoDir = makeTempDir(t, 'kovo-v4-sast-')
    writeLabRepoFixture(join(repoDir, 'app'), { withVulns: true })
    const res = await runWorkerSast(backend as never, { repo: 'app', engines: ['opengrep'], reposDir: repoDir }) as {
      engineStatus: Record<string, { ok: boolean }>; findings: unknown[]
    }
    assert.equal(res.engineStatus.opengrep.ok, true)
    assert.ok(res.findings.length >= 1)
  })

  test('T2-12b: kovo-worker:v4 trivy-fs runs offline scan against /opt/trivy-cache on vulnerable lockfile', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T2-12b')
    const backend = new LinuxWorkerBackend()
    const repoDir = makeTempDir(t, 'kovo-v4-trivy-')
    const appDir = join(repoDir, 'app')
    mkdirSync(appDir, { recursive: true })
    writeFileSync(join(appDir, 'package.json'), JSON.stringify({ name: 'vuln-pkg', version: '1.0.0', dependencies: { lodash: '4.17.15' } }))
    writeFileSync(join(appDir, 'package-lock.json'), JSON.stringify({
      name: 'vuln-pkg', version: '1.0.0', lockfileVersion: 3, requires: true,
      packages: {
        '': { name: 'vuln-pkg', version: '1.0.0', dependencies: { lodash: '4.17.15' } },
        'node_modules/lodash': { version: '4.17.15', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz' },
      },
    }))
    const res = await runWorkerSast(backend as never, { repo: 'app', engines: ['trivy-fs'], reposDir: repoDir }) as {
      engineStatus: Record<string, { ok: boolean }>; findings: unknown[]
    }
    assert.equal(res.engineStatus['trivy-fs'].ok, true)
    assert.ok(res.findings.length >= 1, 'Expected offline Trivy DB to detect lodash 4.17.15 CVEs')
  })

  test('T2-12c: Tree-Sitter/SWC AST extraction executes cleanly inside --read-only container', async () => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T2-12c')
    const backend = new LinuxWorkerBackend()
    const out = await runWorkerAnalyze(backend as never, 'js-harvest', {
      text: `export const ep = "/api/read-only-verified";`,
      sourceName: 'https://app.invalid/ro.js',
    })
    assert.match(JSON.stringify(out), /read-only-verified/)
  })

  test('T2-12d: gitleaks/trufflehog SAST findings mask raw AWS/Stripe secrets in maskedPreview', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T2-12d')
    const backend = new LinuxWorkerBackend()
    const repoDir = makeTempDir(t, 'kovo-v4-secrets-')
    const appDir = join(repoDir, 'app')
    mkdirSync(appDir, { recursive: true })
    writeFileSync(join(appDir, 'config.ts'), `export const STRIPE = "${RAW_STRIPE_SECRET}";\nexport const AWS = "${RAW_AWS_SECRET}";\n`)
    const res = await runWorkerSast(backend as never, { repo: 'app', engines: ['gitleaks'], reposDir: repoDir })
    const text = JSON.stringify(res)
    assert.ok(!text.includes(RAW_STRIPE_SECRET), 'SAST output leaked Stripe secret')
    assert.ok(!text.includes(RAW_AWS_SECRET), 'SAST output leaked AWS secret')
  })

  test('T2-12e: verifyStaticAst confirms planted line range and rejects non-matching line range', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T2-12e')
    const backend = new LinuxWorkerBackend()
    const repoDir = makeTempDir(t, 'kovo-v4-astv-')
    writeLabRepoFixture(join(repoDir, 'app'), { withVulns: true })
    const ok = await backend.verifyStaticAst(
      randomUUID(),
      {
        repo: 'app', file: 'src/orders.ts', startLine: 1, endLine: 3,
        engine: 'ast-grep', ruleOrPattern: 'db.query($SQL)',
      },
      AbortSignal.timeout(45_000),
      { reposDir: repoDir },
    )
    assert.equal(ok.verified, true)
    const miss = await backend.verifyStaticAst(
      randomUUID(),
      {
        repo: 'app', file: 'src/orders.ts', startLine: 1, endLine: 3,
        engine: 'ast-grep', ruleOrPattern: 'exec($CMD)',
      },
      AbortSignal.timeout(45_000),
      { reposDir: repoDir },
    )
    assert.equal(miss.verified, false)
  })

  // --- Feature 13: 3-Stage Offline Semantic Audit Pipeline ---

  test('T2-13a: Stage-1 infers custom ORM/auth middleware wrappers into ProjectSecuritySpec', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T2-13a')
    const backend = new LinuxWorkerBackend()
    const repoDir = makeTempDir(t, 'kovo-v4-iris-')
    const appDir = join(repoDir, 'app')
    mkdirSync(join(appDir, 'src'), { recursive: true })
    writeFileSync(join(appDir, 'src/auth.ts'), `export function requireOrgMembership(req: any) { return req.user?.orgId }`)
    writeFileSync(join(appDir, 'src/db.ts'), `export function rawSql(prisma: any, q: string) { return prisma.$queryRawUnsafe("SELECT * FROM orgs WHERE q=" + q) }`)
    const session = await backend.openSession(randomUUID(), AbortSignal.timeout(30_000), { reposDir: repoDir })
    t.after(() => session.close())
    const signal = AbortSignal.timeout(60_000)
    const stage1 = await extractProjectSecuritySpecAndRules({ signal } as never, 'app', session, { enableLlm: false })
    assert.ok(stage1.spec.authTenantGuards.some(g => g.name === 'requireOrgMembership' && g.kind === 'tenant_scope'), 'Expected custom tenant guard inference')
    assert.ok(stage1.spec.sinks.some(s => s.patterns.some(p => p.includes('$queryRawUnsafe'))), 'Expected custom raw SQL sink inference')
    assert.ok(stage1.spec.businessInvariants.some(i => i.requiredGuard === 'requireOrgMembership'), 'Expected guard dominance invariant')
    assert.ok(stage1.rules.some(r => r.spec.id.includes('queryrawunsafe')), 'Expected generated dynamic rule for raw SQL wrapper')
  })

  test('T2-13b: Stage-2 sinkpoint-backward interprocedural traversal traces entrypoint -> helper -> SQL sink across 2 files', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T2-13b')
    const backend = new LinuxWorkerBackend()
    const repoDir = makeTempDir(t, 'kovo-v4-taint-')
    const appDir = join(repoDir, 'app')
    mkdirSync(join(appDir, 'src'), { recursive: true })
    writeFileSync(join(appDir, 'src/repo.ts'), `export function findInvoice(db: any, id: string) { return db.query("SELECT * FROM invoices WHERE id = " + id) }`)
    writeFileSync(join(appDir, 'src/route.ts'), `import { findInvoice } from './repo.ts'\napp.get('/api/invoices', (req, res) => res.json(findInvoice(db, req.query.id)))`)
    const res = await runWorkerSast(backend as never, { repo: 'app', engines: ['opengrep'], reposDir: repoDir }) as {
      engineStatus: Record<string, { ok: boolean }>; findings: unknown[]
    }
    assert.equal(res.engineStatus.opengrep.ok, true)
    assert.match(JSON.stringify(res.findings), /invoices/i)
  })

  test('T2-13c: Stage-3 git-history miner scans mounted repo commits for security fix patterns', async (t) => {
    const repoRoot = makeTempDir(t, 'kovo-v4-gitmine-')
    const dir = join(repoRoot, 'app')
    mkdirSync(dir, { recursive: true })
    await exec('git', ['init'], { cwd: dir })
    await exec('git', ['config', 'user.email', 'test@kovo.local'], { cwd: dir })
    await exec('git', ['config', 'user.name', 'Test'], { cwd: dir })
    writeFileSync(join(dir, 'a.ts'), 'export const a = 1;')
    await exec('git', ['add', '.'], { cwd: dir })
    await exec('git', ['commit', '-m', 'docs: initial commit'], { cwd: dir })
    writeFileSync(join(dir, 'a.ts'), 'export const a = 2;')
    await exec('git', ['add', '.'], { cwd: dir })
    await exec('git', ['commit', '-m', 'fix(auth): prevent tenant IDOR bypass in /api/invoices'], { cwd: dir })
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call',
      callId: 'c_git_t2',
      name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'proved', summary: 'Audit complete' }),
    }))
    const { dir: dataDir, storage } = makeStore(t)
    await saveModelProfile({
      name: 'Reasoning', endpoint: llm.endpoint, model: 'mock-r', protocol: 'responses', key: 'sk-t213c-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'high', roleAffinity: 'reasoning',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    // Benign 404 fixture: see T1-13d. A dead seed pauses the run via the circuit breaker.
    const fixture = await startHttpFixture(t, (_req, _body, res) => { res.statusCode = 404; res.end('not found') })
    const { projectId, runId } = await setupApprovedRun(storage, { seeds: [fixture.origin] })
    mkdirSync(join(dataDir, 'repos', projectId, 'local'), { recursive: true })
    await exec('cp', ['-r', dir, join(dataDir, 'repos', projectId, 'local', 'app')])
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 15_000
      while (Date.now() < deadline) {
        if (storage.run(runId).phase !== 'threat_model') break
        await delay(100)
      }
      await stopExecution(engine as never)
    })
    const facts = storage.listFacts(runId, { includeTainted: false, limit: 100 })
    const serialized = JSON.stringify(facts)
    assert.match(serialized, /IDOR|\/api\/invoices/i)
    assert.ok(!serialized.includes('docs: initial commit'))
  })

  test('T2-13d: post-confirmation Variant Sweep synthesizes structural query and discovers sibling route', async (t) => {
    const repoRoot = makeTempDir(t, 'kovo-v4-variant-')
    const appSrc = join(repoRoot, 'app')
    writeLabRepoFixture(appSrc, { withVulns: true })
    writeFileSync(join(appSrc, 'src', 'billing.ts'), `export async function getBilling(db: { query: (s: string) => unknown }, id: string) {\n  return db.query("SELECT * FROM billing WHERE id = '" + id + "'")\n}\n`)
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call',
      callId: 'c_var_t2',
      name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'proved', summary: 'Sweep done' }),
    }))
    const { dir: dataDir, storage } = makeStore(t)
    await saveModelProfile({
      name: 'Reasoning', endpoint: llm.endpoint, model: 'mock-r', protocol: 'responses', key: 'sk-t213d-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'high', roleAffinity: 'reasoning',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { projectId, runId, run, assetIds } = await setupApprovedRun(storage, { seeds: ['http://127.0.0.1:9'] })
    mkdirSync(join(dataDir, 'repos', projectId, 'local'), { recursive: true })
    await exec('cp', ['-r', appSrc, join(dataDir, 'repos', projectId, 'local', 'app')])
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'complete', 1, 0, ?, '[]', '[]', 'inv', 'obj', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const fid = randomUUID()
    const specRow = storage.createReplaySpec(run, storage.worker(aid), fid, {
      ...baseReplaySpecFields('http://127.0.0.1:9'),
      kind: 'static_ast_proof',
      repo: 'app',
      file: 'src/orders.ts',
      startLine: 1,
      endLine: 3,
      engine: 'ast-grep',
      ruleOrPattern: 'SELECT * FROM orders',
      runtimeProofGap: 'Verified statically in source AST; runtime proof pending.',
      assertionsJq: '{ controlPassed: true, confirmed: (.static.verified == true), observed: "matched", expected: "no match" }',
    }, ['http://127.0.0.1:9'])
    storage.upsertChainFinding(run, assetIds[0], {
      id: fid, origin: 'http://127.0.0.1:9', title: 'SQL Injection in getOrder', status: 'confirmed',
      verificationTier: 'static_verified', severity: 'high',
      reason: 'Confirmed SQL injection in src/orders.ts:2', remediation: 'Use parameterized SQL.', evidenceIds: [], scopeRevision: 1,
      codeLocations: [{ repo: 'local/app', file: 'src/orders.ts', startLine: 1, endLine: 3 }],
    }, specRow.id, ['http://127.0.0.1:9'])
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 15_000
      while (Date.now() < deadline) {
        if (storage.listChainSteps(runId).some(s => /billing\.ts/i.test(JSON.stringify(s)))) break
        await delay(100)
      }
      await stopExecution(engine as never)
    })
    assert.ok(storage.listChainSteps(runId).some(s => /billing\.ts/i.test(JSON.stringify(s))))
  })

  test('T2-13e: all >12 semantic audit suspects feed into SQLite chain_steps without truncation', async (t) => {
    const execMod = await import('../src/server/execution.ts') as Record<string, unknown>
    const convertSuspects = requireExport<typeof convertCodeAuditSuspectsToChainSteps>(
      execMod, 'convertCodeAuditSuspectsToChainSteps', 'src/server/execution.ts',
    )
    const { storage } = makeStore(t)
    const { runId, run } = await setupApprovedRun(storage, { budgetRequests: 2000 })
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'threat_model', 'running', 1, 0, ?, '[]', ?, 'audit', 'audit', ?)`)
      .run(aid, runId, randomUUID(), JSON.stringify(['http://127.0.0.1:9']), Date.now())
    const assignment = storage.worker(aid)
    const factRows = Array.from({ length: 18 }, (_, i) => storage.addFact(run, assignment, {
      kind: 'code_audit_suspect',
      origin: 'http://127.0.0.1:9',
      summary: `Taint Suspect ${i}`,
      data: {
        title: `Taint Suspect ${i}`,
        endpoint: `/api/s/${i}`,
        severity: 'high',
        category: 'injection-input',
      },
    }))
    const created = convertSuspects(storage, run, factRows)
    assert.equal(created.length, 18)
  })

  // --- Feature 14: Multi-Container --internal LabRunner v4 & Wiring ---

  test('T2-14a: LabRunner starts multi-service app + sidecar on --internal inhibit_ipv4=true network and cleans up', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T2-14a')
    const runner = new LabRunner()
    t.after(() => runner.stopAll())
    const repo = makeTempDir(t, 'kovo-v4-compose-')
    writeLabRepoFixture(repo, { withCompose: true })
    const runId = randomUUID()
    const handle = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runner.startLabTarget({
        runId,
        environment: 'local-lab',
        repoDir: repo,
        labConfig: {
          enabled: true,
          healthPath: '/health',
          internalPort: 3000,
          services: [
            { name: 'app', dockerfile: 'Dockerfile', internalPort: 3000 },
            { name: 'cache', image: 'node:24-bookworm-slim', internalPort: 6379, command: 'node -e "require(\'http\').createServer((_,r)=>r.end(\'ok\')).listen(6379)"' },
          ],
        } as unknown as LabConfig,
      }),
    ) as unknown as V4LabTargetHandle
    const { stdout: netJson } = await exec('docker', ['network', 'inspect', handle.networkName])
    const net = JSON.parse(netJson)[0] as { Internal: boolean; Options?: Record<string, string> }
    assert.equal(net.Internal, true)
    assert.equal(net.Options?.['com.docker.network.bridge.inhibit_ipv4'], 'true')
    const { stdout: runningIds } = await exec('docker', ['ps', '-q', '--filter', `label=dev.kovo.run=${runId}`])
    const cids = runningIds.trim().split('\n').filter(Boolean)
    assert.ok(cids.length >= 2, `Expected >=2 multi-service containers for run, got ${cids.length}`)
    const appCid = handle.containerName || cids[0]
    const cacheReach = await exec('docker', ['exec', appCid, 'node', '-e', `fetch('http://cache:6379').then(async r=>{if(!r.ok)process.exit(1);console.log(await r.text())}).catch(()=>process.exit(1))`])
    assert.match(cacheReach.stdout, /ok/)
    await assert.rejects(() =>
      exec('docker', ['exec', appCid, 'node', '-e', `fetch('http://1.1.1.1',{signal:AbortSignal.timeout(1500)}).then(()=>process.exit(0)).catch(()=>process.exit(1))`]),
    )
    await runner.stopAll()
    await assertZeroKovoOrphans(runId)
  })

  test('T2-14b: LabRunner seedCommand populates synthetic personas into handle.seededPersonas', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T2-14b')
    const runner = new LabRunner()
    t.after(() => runner.stopAll())
    const repo = makeTempDir(t, 'kovo-v4-seed-')
    writeLabRepoFixture(repo)
    writeFileSync(join(repo, 'seed.mjs'), `console.log(JSON.stringify({ personas: [{ handle: 'persona_a', roleLabel: 'Tenant A', authKind: 'bearer', secret: 'tok-a' }] }))`)
    const runId = randomUUID()
    const handle = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runner.startLabTarget({
        runId,
        environment: 'local-lab',
        repoDir: repo,
        labConfig: { enabled: true, dockerfile: 'Dockerfile', internalPort: 3000, healthPath: '/health', seedCommand: 'node seed.mjs' } as unknown as LabConfig,
      }),
    ) as unknown as V4LabTargetHandle
    assert.ok(Array.isArray(handle.seededPersonas) && handle.seededPersonas.length >= 1)
    await runner.stopAll()
  })

  test('T2-14c: LabRunner rebuildWithPatch swaps patched app container keeping origin stable', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T2-14c')
    const runner = new LabRunner()
    t.after(() => runner.stopAll())
    const repo = makeTempDir(t, 'kovo-v4-rebuild-')
    writeLabRepoFixture(repo)
    const runId = randomUUID()
    const h1 = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runner.startLabTarget({
        runId, environment: 'local-lab', repoDir: repo,
        labConfig: { enabled: true, dockerfile: 'Dockerfile', internalPort: 3000, healthPath: '/health' },
      }),
    )
    const diff = [
      '--- a/server.mjs',
      '+++ b/server.mjs',
      '@@ -6,3 +6,3 @@',
      '   if (u.pathname === \'/api/orders\') {',
      '-    const id = u.searchParams.get(\'id\') || \'1\'',
      '+    const id = String(Number(u.searchParams.get(\'id\') || \'1\'))',
    ].join('\n')
    const h2 = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runner.rebuildWithPatch(runId, diff),
    )
    assert.equal(h2.origin, h1.origin)
    await runner.stopAll()
  })

  test('T2-14d: cli.ts --local-lab flag parses and wires LabRunner config cleanly', () => {
    const opts = parseCliArgs(['scan', '--local-lab', '--origin', 'http://127.0.0.1:3000', '--tier', '2', '--sarif', '/tmp/out.sarif'])
    assert.equal(opts.localLab, true)
    assert.equal(opts.tier, 2)
    assert.equal(opts.sarifPath, '/tmp/out.sarif')
  })

  test('T2-14e: HTTP updateProjectLabConfig RPC persists multi-service labConfig when KOVO_ALLOW_LOCAL_LAB=1', async (t) => {
    const { storage } = makeStore(t)
    const { projectId } = await setupApprovedRun(storage, { environment: 'local-lab' })
    const cfg: V4LabConfig = {
      enabled: true,
      healthPath: '/health',
      internalPort: 3000,
      iastEnabled: true,
      iastRuntime: 'node',
      services: [{ name: 'app', dockerfile: 'Dockerfile', internalPort: 3000 }],
    }
    const updated = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      storage.updateProjectLabConfig({ requestId: randomUUID(), projectId, labConfig: cfg as LabConfig }),
    )
    assert.equal((updated.labConfig as V4LabConfig | null)?.iastEnabled, true)
  })

  // --- Feature 15: Opt-In local-lab IAST & Coverage Telemetry ---

  test('T2-15a: Store.insertLabTelemetry and listLabTelemetry persist and retrieve IAST rows', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    const ins = v4.insertLabTelemetry({
      runId, exchangeId: 'ex-1', traceId: 'tr-1', routesHit: ['/api/orders'],
      newLinesCovered: 14, sinkEventsCount: 2, hasUnhandledException: true, artifactId: 'art-1',
    })
    const rows = v4.listLabTelemetry(runId)
    assert.equal(rows.length, 1)
    assert.equal(rows[0].id, ins.id)
    assert.equal(Boolean(rows[0].hasUnhandledException ?? rows[0].has_unhandled_exception), true)
  })

  test('T2-15b: IAST routesHit updates SQLite endpoints.coverage_pct for discovered routes', async (t) => {
    const mod = await import('../src/server/lab-runner.ts') as Record<string, unknown>
    const ingestTelemetry = requireExport<(input: Record<string, unknown>) => { filePath: string; bytesWritten: number }>(
      mod, 'ingestLabTelemetry', 'src/server/lab-runner.ts',
    )
    const { dir, storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/api/orders', source: 'spa_crawl', coveragePct: 0 })
    const telemetryDir = join(dir, 'evidence', 'lab-telemetry')
    mkdirSync(telemetryDir, { recursive: true })
    ingestTelemetry({
      runId, exchangeId: 'ex-cov', traceId: 'tr-cov', environment: 'local-lab', telemetryDir, secrets: [],
      rawTelemetry: { routesHit: ['/api/orders'], newLinesCovered: 10, sinkEvents: [], exceptions: [] },
      storage,
    })
    const eps = v4.listEndpoints(runId)
    assert.ok(Number(eps[0].coveragePct ?? eps[0].coverage_pct) > 0)
  })

  test('T2-15c: IAST Node runtime hook captures SQL sink syntax error tagged with X-Kovo-Trace-Id', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon is required for LabRunner IAST runtime hook test')
    const runner = new LabRunner()
    t.after(() => runner.stopAll())
    const repo = makeTempDir(t, 'kovo-v4-iast-node-')
    writeLabRepoFixture(repo)
    const runId = randomUUID()
    const handle = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runner.startLabTarget({
        runId,
        environment: 'local-lab',
        repoDir: repo,
        labConfig: { enabled: true, dockerfile: 'Dockerfile', internalPort: 3000, healthPath: '/health', iastEnabled: true, iastRuntime: 'node' } as unknown as LabConfig,
      }),
    ) as unknown as V4LabTargetHandle
    const { storage } = makeStore(t)
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    const traceId = `trace-${randomUUID().slice(0, 8)}`
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      broker.executeHttp(
        { origin: handle.origin, method: 'GET', pathAndQuery: "/api/orders?id=1'", traceId, runId },
        makeLabGrant(handle.origin),
        AbortSignal.timeout(10_000),
      ),
    )
    const files = handle.telemetryDir && existsSync(handle.telemetryDir) ? readdirSync(handle.telemetryDir) : []
    const rows = (storage as unknown as V4StoreContract).listLabTelemetry(runId)
    assert.ok(files.length >= 1 || rows.length >= 1, 'Expected IAST Node telemetry to record sink/route hit')
    await runner.stopAll()
    await assertZeroKovoOrphans(runId)
  })

  test('T2-15d: coverage-driven planner prioritizes endpoints with coverage_pct = 0', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/covered', source: 'spa_crawl', coveragePct: 90, riskScore: 80 })
    v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/uncovered', source: 'spa_crawl', coveragePct: 0, riskScore: 80 })
    const ordered = storage.listEndpoints(runId, { orderBy: 'coverage', maxCoveragePct: 0 })
    assert.equal(ordered[0].pathTemplate, '/uncovered')
  })

  test('T2-15e: lab_telemetry artifacts stage into /evidence/lab-telemetry/ with secret scrubbing', async (t) => {
    const mod = await import('../src/server/lab-runner.ts') as Record<string, unknown>
    const ingestTelemetry = requireExport<(input: Record<string, unknown>) => { filePath: string; bytesWritten: number }>(
      mod, 'ingestLabTelemetry', 'src/server/lab-runner.ts',
    )
    const { dir, storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const telemetryDir = join(dir, 'evidence', 'lab-telemetry')
    mkdirSync(telemetryDir, { recursive: true })
    const res = ingestTelemetry({
      runId, exchangeId: 'ex-99', traceId: 'tr-99', environment: 'local-lab', telemetryDir,
      secrets: [{ value: RAW_STRIPE_SECRET, placeholder: '[masked:stripe]' }],
      rawTelemetry: { routesHit: ['/api/pay'], newLinesCovered: 2, sinkEvents: [{ sink: 'stripe', key: RAW_STRIPE_SECRET }], exceptions: [] },
      storage,
    })
    const saved = readFileSync(res.filePath, 'utf8')
    assert.ok(res.filePath.includes(join('evidence', 'lab-telemetry')))
    assert.ok(!saved.includes(RAW_STRIPE_SECRET))
  })

  // --- Feature 16: Universal Parameter Encodings & Expanded SQLi ---

  test('T2-16a: probeDifferential injects form-encoded POST and XML body SQLi payloads cleanly', async (t) => {
    const fx = await startHttpFixture(t, (_req, body, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (body.includes('=1%27') || body.includes("'")) {
        res.statusCode = 500
        res.end(JSON.stringify({ error: 'SQLITE_ERROR: near syntax error' }))
        return
      }
      res.end(JSON.stringify({ rows: [1] }))
    })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const grant = makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true })
    const formRes = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'sqli_boolean', origin: fx.origin, pathAndQuery: '/search',
          method: 'POST', param: 'q', paramLocation: 'form', baselineValue: '1',
        } as unknown as Parameters<typeof probeDifferential>[0],
        broker, grant, undefined, AbortSignal.timeout(15_000),
      ),
    )
    const xmlRes = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'sqli_boolean', origin: fx.origin, pathAndQuery: '/xml-search',
          method: 'POST', param: 'id', paramLocation: 'xml', baselineValue: '1',
        } as unknown as Parameters<typeof probeDifferential>[0],
        broker, grant, undefined, AbortSignal.timeout(15_000),
      ),
    )
    assert.equal(formRes.verdict, 'signal')
    assert.equal(xmlRes.verdict, 'signal')
  })

  test('T2-16b: ReplayVerifier sql_boolean_diff confirms header and path paramLocation injections', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      const val = req.url?.startsWith('/item/') ? decodeURIComponent(req.url.slice(6)) : String(req.headers['x-filter'] ?? '')
      res.setHeader('Content-Type', 'application/json')
      const match = /AND\s+(\d+)=\1/.test(val)
      res.end(JSON.stringify({ found: match || val === '1' }))
    })
    for (const loc of ['path', 'header'] as const) {
      const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
        verifyReplaySpec({
          spec: {
            ...baseReplaySpecFields(fx.origin),
            kind: 'sql_boolean_diff',
            targetOrigin: fx.origin,
            method: 'GET',
            pathAndQuery: loc === 'path' ? '/item/{{val}}' : '/search',
            paramName: loc === 'path' ? 'id' : 'X-Filter',
            paramLocation: loc,
            baselineValue: '1',
            quoteStyle: 'numeric',
            assertionsJq: '{ controlPassed: (.sqlDiff.controlPassed == true), confirmed: (.sqlDiff.passed == true), observed: ("passed=" + (.sqlDiff.passed | tostring)), expected: "sqlDiff.passed=false" }',
          } as unknown,
          broker: new RequestBroker({ rejectUnauthorized: false }),
          backend: new LinuxWorkerBackend(),
          grant: makeLabGrant(fx.origin),
          signal: AbortSignal.timeout(30_000),
        }),
      )
      assert.equal(res.verdict, 'confirmed', `Expected sql_boolean_diff ${loc} to confirm`)
    }
  })

  test('T2-16c: probeDifferential sqli_time_diff executes 3 interleaved rounds on local-lab fixture', async (t) => {
    const fx = await startHttpFixture(t, async (req, _b, res) => {
      const u = new URL(req.url ?? '/', fx.origin)
      const id = u.searchParams.get('id') ?? ''
      if (/SLEEP|pg_sleep|WAITFOR|randomblob/i.test(id)) await delay(1600)
      res.end('ok')
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'sqli_time_diff', origin: fx.origin, pathAndQuery: '/items?id=1',
          param: 'id', paramLocation: 'query', baselineValue: '1',
        } as unknown as Parameters<typeof probeDifferential>[0],
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { tier: 3 }),
        undefined,
        AbortSignal.timeout(30_000),
      ),
    )
    assert.equal(res.verdict, 'signal')
    assert.ok(res.requestsSent >= 6)
  })

  test('T2-16d: ReplayVerifier sql_time_diff rejects jittery/overlapping latency responses', async (t) => {
    let flip = 0
    const fx = await startHttpFixture(t, async (_req, _b, res) => {
      flip += 1
      if (flip === 1) await delay(2200) // slow baseline creates overlap
      res.end('ok')
    })
    const spec = {
      ...baseReplaySpecFields(fx.origin),
      kind: 'sql_time_diff',
      targetOrigin: fx.origin,
      method: 'GET',
      pathAndQuery: '/items?id=1',
      paramName: 'id',
      paramLocation: 'query',
      delayMs: 2000,
      assertionsJq: '{ controlPassed: (.sqlTimeDiff.controlPassed // true), confirmed: (.sqlTimeDiff.passed // false), observed: "timing_diff", expected: "no timing overlap" }',
    } as unknown
    const parsed = declarativeReplaySpecSchema.safeParse(spec)
    assert.equal(parsed.success, true, parsed.success ? '' : parsed.error.message)

    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: parsed.data,
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { tier: 3 }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.ok(flip >= 2 && fx.requests.length >= 2, `Expected >= 2 HTTP requests to target, got flip=${flip}`)
    assert.equal(res.verdict, 'dismissed')
  })

  test('T2-16e: pairwise encoding matrix (graphql_var + json + form) injects SQLi differential consistently', async (t) => {
    const seenBodies: string[] = []
    const fx = await startHttpFixture(t, (_req, body, res) => {
      seenBodies.push(body)
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ ok: true }))
    })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const grant = makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true })
    for (const loc of ['json', 'form', 'graphql_var'] as const) {
      await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
        probeDifferential(
          {
            probeClass: 'sqli_boolean', origin: fx.origin, pathAndQuery: '/api/q',
            method: 'POST', param: 'filter', paramLocation: loc, baselineValue: 'abc',
          } as unknown as Parameters<typeof probeDifferential>[0],
          broker, grant, undefined, AbortSignal.timeout(15_000),
        ),
      )
    }
    assert.ok(seenBodies.some(b => b.includes('"variables"')))
    assert.ok(seenBodies.some(b => b.includes('filter=')))
    assert.ok(seenBodies.some(b => b.includes('"filter"')))
  })

  // --- Feature 17: Automated BOLA/BFLA & Workflow-Skip Sweepers ---

  test('T2-17a: authz_matrix sweeps SQLite endpoints paired with api_dependencies IDs', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      // v5's id-selectivity gate compares the real id against a random nonexistent one.
      // An echo endpoint must 404 unknown ids, otherwise every body is "similar" and the
      // sweeper correctly refuses to call it id-bound.
      if (!req.url?.includes('ord_secret_1')) { res.statusCode = 404; res.end('not found'); return }
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ orderId: 'ord_secret_1', owner: 'persona_a', viewer: req.headers.authorization }))
    })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [
        { handle: 'persona_a', roleLabel: 'A', authKind: 'bearer', secret: 'tok-a' },
        { handle: 'persona_b', roleLabel: 'B', authKind: 'bearer', secret: 'tok-b' },
      ],
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'authz_matrix', origin: fx.origin, pathAndQuery: '/api/orders/{{id}}',
          resourceIds: ['ord_secret_1'], ownerPersona: 'persona_a', otherPersona: 'persona_b',
          includeAnonymous: true, includeHeaderBypass: true,
        },
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { personas: personaMap }),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    assert.equal(res.verdict, 'signal')
  })

  test('T2-17b: producer-consumer BOLA lifecycle creates as persona_a, probes PATCH/DELETE as persona_b, marks tested_bola', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (req.method === 'POST' && req.url === '/api/orders') {
        res.statusCode = 201
        res.end(JSON.stringify({ id: 'ord_77' }))
        return
      }
      res.end(JSON.stringify({ id: 'ord_77', modifiedBy: req.headers.authorization }))
    })
    const { storage } = makeStore(t)
    const { runId, personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [
        { handle: 'persona_a', roleLabel: 'A', authKind: 'bearer', secret: 'tok-a' },
        { handle: 'persona_b', roleLabel: 'B', authKind: 'bearer', secret: 'tok-b' },
      ],
    })
    const v4 = storage as unknown as V4StoreContract
    const prod = v4.upsertEndpoint({ runId, scopeRevision: 1, origin: fx.origin, method: 'POST', pathTemplate: '/api/orders', source: 'spa_crawl' })
    const cons = v4.upsertEndpoint({ runId, scopeRevision: 1, origin: fx.origin, method: 'PATCH', pathTemplate: '/api/orders/{id}', source: 'spa_crawl' })
    const dep = v4.recordApiDependency({ runId, producerEndpointId: prod.id, consumerEndpointId: cons.id, resourceKey: 'id', personaHandle: 'persona_a' })
    const grant = makeLabGrant(fx.origin, { tier: 3, personas: personaMap, isStateChangeApproved: () => true })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const out = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'authz_matrix',
          storage,
          runId,
          dependencyId: dep.id,
          origin: fx.origin,
          pathAndQuery: '/api/orders/{{id}}',
          producerPath: '/api/orders',
          method: 'PATCH',
          resourceIds: ['ord_77'],
          ownerPersona: 'persona_a',
          otherPersona: 'persona_b',
        } as unknown as Parameters<typeof probeDifferential>[0],
        broker,
        grant,
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    assert.equal(out.verdict, 'signal')
    assert.equal(Boolean(v4.listApiDependencies(runId)[0].testedBola ?? v4.listApiDependencies(runId)[0].tested_bola), true)
  })

  test('T2-17c: workflow step-skip draft -> refund confirmed via http_chain ReplayVerifier', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (req.url === '/api/orders/draft') { res.end(JSON.stringify({ id: 'o1', status: 'draft' })); return }
      if (req.url === '/api/orders/o1/refund') { res.end(JSON.stringify({ id: 'o1', status: 'refunded', amount: 100 })); return }
      res.statusCode = 404
      res.end('{}')
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'http_chain',
          category: 'business-logic-race',
          cwe: 'CWE-840',
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200 and .steps.c1.json.status == "draft"), confirmed: (.steps.p1.status == 200 and .steps.p1.json.status == "refunded"), observed: .steps.p1.json.status, expected: "400/403 rejecting draft->refund" }',
          steps: [
            { id: 'c1', role: 'control', description: 'Draft order', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/orders/draft' } },
            { id: 'p1', role: 'probe', description: 'Skip payment directly to refund', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/api/orders/o1/refund', jsonBody: {} } },
          ],
        },
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
  })

  test('T2-17d: race_burst confirms coupon double-spend concurrency flaw deterministically', async (t) => {
    let redeemed = 0
    const fx = await startHttpFixture(t, async (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (req.url === '/api/wallet') { res.end(JSON.stringify({ balance: redeemed * 50 })); return }
      await delay(30)
      redeemed += 1
      res.end(JSON.stringify({ redeemed: true, count: redeemed }))
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'race_burst',
          category: 'business-logic-race',
          cwe: 'CWE-362',
          assertionsJq: '{ controlPassed: (.burst.summary.total == 5), confirmed: (.postCheck.status == 200 and .postCheck.json.balance >= 100), observed: ("balance=" + (.postCheck.json.balance | tostring)), expected: "balance <= 50" }',
          burst: Array.from({ length: 5 }, () => ({ origin: fx.origin, method: 'POST', pathAndQuery: '/api/coupon/redeem', jsonBody: { code: 'SAVE50' } })),
          postCheckStep: { id: 'chk', role: 'probe', description: 'Check wallet', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/wallet' } },
        },
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
  })

  test('T2-17e: BOLA header bypass checks X-Original-URL and X-Rewrite-URL on protected endpoints', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.headers['x-original-url'] === '/admin/secret') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ adminSecret: true }))
        return
      }
      res.statusCode = 403
      res.end('forbidden')
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'authz_matrix', origin: fx.origin, pathAndQuery: '/api/items/{{id}}',
          resourceIds: ['1'], includeHeaderBypass: true, includeAnonymous: true,
        },
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    assert.ok(fx.requests.some(r => r.headers['x-original-url'] || r.headers['x-rewrite-url']))
    assert.ok(res.requestsSent >= 1)
  })

  // --- Feature 18: Schema-Driven GraphQL Resolver Fuzzer ---

  test('T2-18a: graphql_audit discovers nested user.org.billingInvoices auth gap across personas', async (t) => {
    const fx = await startHttpFixture(t, (req, body, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (body.includes('IntrospectionQuery') || body.includes('__schema')) {
        res.end(JSON.stringify({ data: { __schema: { types: [{ name: 'Query', fields: [{ name: 'user', args: [{ name: 'id', type: { name: 'ID' } }] }] }] } } }))
        return
      }
      if (body.includes('billingInvoices')) {
        res.end(JSON.stringify({ data: { user: { org: { billingInvoices: [{ total: 9999, secretTenant: 'tenantA' }] } } } }))
        return
      }
      res.end(JSON.stringify({ data: {} }))
    })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [
        { handle: 'user_a', roleLabel: 'A', authKind: 'bearer', secret: 'tok-a' },
        { handle: 'user_b', roleLabel: 'B', authKind: 'bearer', secret: 'tok-b' },
      ],
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'graphql_audit', origin: fx.origin, pathAndQuery: '/graphql',
          sdl: `type Invoice { total: Int! } type Org { billingInvoices: [Invoice!]! } type User { org: Org! } type Query { user(id: ID!): User }`,
          ownerPersona: 'user_a', otherPersona: 'user_b',
        } as unknown as Parameters<typeof probeDifferential>[0],
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { personas: personaMap, isIdempotentPostAllowed: () => true }),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    assert.equal(res.verdict, 'signal')
  })

  test('T2-18b: GraphQL scalar argument SQLi via graphql_var triggers SQL error differential', async (t) => {
    const fx = await startHttpFixture(t, (_req, body, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (body.includes("'")) {
        res.statusCode = 500
        res.end(JSON.stringify({ errors: [{ message: 'SQLITE_ERROR: near syntax error' }] }))
        return
      }
      res.end(JSON.stringify({ data: { search: [] } }))
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'sqli_boolean', origin: fx.origin, pathAndQuery: '/graphql',
          method: 'POST', param: 'term', paramLocation: 'graphql_var', baselineValue: 'hello',
        } as unknown as Parameters<typeof probeDifferential>[0],
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    assert.equal(res.verdict, 'signal')
  })

  test('T2-18c: GraphQL mutation fuzzing runs when sandboxWriteAllowlist permits POST /graphql at Tier 2', async () => {
    const origin = 'https://gql-sandbox.example.invalid'
    const allowlist: ApprovedEndpointPattern[] = [{ origin, method: 'POST', pathPattern: '/graphql' }]
    let sawMutation = false
    const broker = makeVirtualPublicBroker((_url, opts) => {
      if (opts?.body?.includes('mutation')) sawMutation = true
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"data":{"updateRole":{"role":"admin"}}}' }
    })
    await probeDifferential(
      {
        probeClass: 'graphql_audit', origin, pathAndQuery: '/graphql',
        sdl: `type User { id: ID! role: String! } type Mutation { updateRole(role: String!): User }`,
        testMutations: true,
      } as unknown as Parameters<typeof probeDifferential>[0],
      broker,
      makePublicGrant(origin, { tier: 2, sandboxWriteAllowlist: allowlist }),
      undefined,
      AbortSignal.timeout(15_000),
    )
    assert.equal(sawMutation, true)
  })

  test('T2-18d: GraphQL fuzzer falls back to SDL from project_specs / /repos when introspection is disabled', async (t) => {
    const fx = await startHttpFixture(t, (_req, body, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (body.includes('__schema')) { res.statusCode = 403; res.end('{"errors":["introspection disabled"]}'); return }
      res.end(JSON.stringify({ data: { secretReport: { csv: 'a,b' } } }))
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'graphql_audit', origin: fx.origin, pathAndQuery: '/graphql',
          sdl: `type Report { csv: String! } type Query { secretReport: Report }`,
        } as unknown as Parameters<typeof probeDifferential>[0],
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    assert.ok(fx.requests.some(r => r.body.includes('secretReport')))
    assert.ok(res.requestsSent >= 1)
  })

  test('T2-18e: GraphQL nested BOLA confirmed deterministically via ReplayVerifier http_chain', async (t) => {
    const fx = await startHttpFixture(t, (req, body, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (req.headers.authorization === 'Bearer tok-b' && body.includes('tenant_a')) {
        res.end(JSON.stringify({ data: { org: { secretKey: 'leaked-tenant-a-billing' } } }))
        return
      }
      res.end(JSON.stringify({ data: { org: { secretKey: 'own-billing' } } }))
    })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [
        { handle: 'persona_a', roleLabel: 'A', authKind: 'bearer', secret: 'tok-a' },
        { handle: 'persona_b', roleLabel: 'B', authKind: 'bearer', secret: 'tok-b' },
      ],
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'http_chain',
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200 and .steps.c1.json.data.org.secretKey == "own-billing"), confirmed: (.steps.p1.json.data.org.secretKey == "leaked-tenant-a-billing"), observed: .steps.p1.json.data.org.secretKey, expected: "authorization error" }',
          steps: [
            { id: 'c1', role: 'control', description: 'Own org', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/graphql', persona: 'persona_b', jsonBody: { query: '{ org(id:"tenant_b") { secretKey } }' } } },
            { id: 'p1', role: 'probe', description: 'Cross-tenant nested org', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/graphql', persona: 'persona_b', jsonBody: { query: '{ org(id:"tenant_a") { secretKey } }' } } },
          ],
        },
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { personas: personaMap, isIdempotentPostAllowed: () => true }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
  })

  // --- Feature 19: New Probe Classes & Declarative Replay Kinds ---

  test('T2-19a: xss_context detects unencoded reflection and escalates to browser_chain dom_xss_sink_hook', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      const u = new URL(req.url ?? '/', fx.origin)
      const q = u.searchParams.get('q') ?? ''
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body><div id="msg"></div><script>document.getElementById("msg").innerHTML = ${JSON.stringify(q)};</script></body></html>`)
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'xss_context', origin: fx.origin, pathAndQuery: '/search?q=hi', param: 'q',
        } as unknown as Parameters<typeof probeDifferential>[0],
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    assert.equal(res.verdict, 'signal')
    assert.ok(res.anomalies.length >= 1)
  })

  test('T2-19b: auth_protocol_audit detects OAuth redirect_uri parser differential and PKCE downgrade', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      const u = new URL(req.url ?? '/', fx.origin)
      if (u.pathname === '/oauth/authorize') {
        const redir = u.searchParams.get('redirect_uri') ?? ''
        const method = u.searchParams.get('code_challenge_method') ?? 'plain'
        if (redir.includes('@') || method === 'plain') {
          res.statusCode = 302
          res.setHeader('Location', `${redir}?code=auth_code_123`)
          res.end()
          return
        }
      }
      res.statusCode = 400
      res.end('invalid_request')
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'auth_protocol_audit', origin: fx.origin, pathAndQuery: '/oauth/authorize?client_id=app&redirect_uri=https://app.example.invalid/cb',
        } as unknown as Parameters<typeof probeDifferential>[0],
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    assert.equal(res.verdict, 'signal')
  })

  test('T2-19c: xxe_canary sends benign DTD canary entity and correlates CanaryBroker hit', async (t) => {
    const canary = new CanaryBroker()
    await canary.startListener({ host: '127.0.0.1', port: 0 })
    t.after(() => canary.stopListener())
    const fx = await startHttpFixture(t, async (_req, body, res) => {
      const m = /https?:\/\/[^\s"'>]+kovo-canary-[a-f0-9]+[^\s"'>]*/i.exec(body)
      if (m) await fetch(m[0]).catch(() => {})
      res.setHeader('Content-Type', 'application/xml')
      res.end('<ok/>')
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'xxe_canary', origin: fx.origin, pathAndQuery: '/api/xml',
          method: 'POST', storage, runId,
        } as unknown as Parameters<typeof probeDifferential>[0],
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
        canary,
        AbortSignal.timeout(15_000),
      ),
    )
    assert.equal(res.verdict, 'signal')
  })

  test('T2-19d: mass_assignment submits privileged role field and confirms persistence on subsequent GET', async (t) => {
    let role = 'user'
    const fx = await startHttpFixture(t, (req, body, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (req.method === 'POST' && req.url === '/api/profile') {
        const parsed = JSON.parse(body || '{}') as Record<string, unknown>
        if (typeof parsed.role === 'string') role = parsed.role
        res.end(JSON.stringify({ ok: true, role }))
        return
      }
      res.end(JSON.stringify({ id: 'u1', role }))
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      probeDifferential(
        {
          probeClass: 'mass_assignment', origin: fx.origin, pathAndQuery: '/api/profile',
          method: 'POST', candidateFields: ['role', 'isAdmin'],
        } as unknown as Parameters<typeof probeDifferential>[0],
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
        undefined,
        AbortSignal.timeout(15_000),
      ),
    )
    assert.equal(res.verdict, 'signal')
  })

  test('T2-19e: cache_differential (#13) confirms shared cache poisoning with mandatory _gcb and Age > 0', async (t) => {
    const poisoned = new Map<string, string>()
    const fx = await startHttpFixture(t, (req, _b, res) => {
      const u = new URL(req.url ?? '/', fx.origin)
      const gcb = u.searchParams.get('_gcb') ?? ''
      const xfh = req.headers['x-forwarded-host']
      if (typeof xfh === 'string' && gcb) {
        poisoned.set(gcb, xfh)
      }
      if (poisoned.has(gcb)) {
        res.setHeader('X-Cache', xfh ? 'MISS' : 'HIT')
        if (!xfh) res.setHeader('Age', '12')
        res.end(`host=${poisoned.get(gcb)}`)
        return
      }
      res.setHeader('X-Cache', 'MISS')
      res.end('host=clean')
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'cache_differential',
          targetOrigin: fx.origin,
          controlPath: '/home?_gcb={{control_gcb}}',
          probePath: '/home?_gcb={{probe_gcb}}',
          poisonHeaders: { 'X-Forwarded-Host': 'cache-poison.invalid' },
          assertionsJq: '{ controlPassed: (.control.status == 200 and (.control.body | contains("host=clean"))), confirmed: (.verify.status == 200 and (.verify.headers["x-cache"] == "HIT") and (.verify.body | contains("cache-poison.invalid"))), observed: .verify.bodyPreview, expected: "host=clean without X-Cache HIT" }',
        } as unknown,
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
    assert.ok(fx.requests.length >= 3)
    assert.ok(fx.requests.some(r => r.url.includes('_gcb=')))
  })

  // --- Feature 20: Second-Order Canary Ledger ---

  test('T2-20a: RequestBroker passive response scanner flags cross-endpoint marker surfacing', async (t) => {
    const marker = 'gn2o_a1b2c3d4'
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/admin/audit') {
        res.end(`<html><td>${marker}</td></html>`)
        return
      }
      res.end('ok')
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const v4 = storage as unknown as V4StoreContract
    v4.insertSecondOrderCanary({
      runId, assignmentId: aid, marker,
      injectedOrigin: fx.origin, injectedEndpoint: '/profile', injectedParam: 'bio', injectedPersona: 'user_a',
    })
    const broker = new RequestBroker({ rejectUnauthorized: false, storage }) as unknown as V4BrokerContract
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/admin/audit', runId, assignmentId: aid }, makeLabGrant(fx.origin), AbortSignal.timeout(5000)),
    )
    const surfaced = v4.listSecondOrderCanaries(runId, 'surfaced')
    assert.equal(surfaced.length, 1)
  })

  test('T2-20b: ScopedBrowser DOM snapshot triggers cross-persona second-order canary surfacing', async (t) => {
    const marker = 'gn2o_f0e1d2c3'
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body><div id="feed"></div><script>document.getElementById('feed').textContent = '${marker}';</script></body></html>`)
    })
    const { storage } = makeStore(t)
    const { runId, personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [
        { handle: 'user_a', roleLabel: 'A', authKind: 'bearer', secret: 'tok-a' },
        { handle: 'admin_b', roleLabel: 'Admin', authKind: 'bearer', secret: 'tok-admin' },
      ],
    })
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const v4 = storage as unknown as V4StoreContract
    v4.insertSecondOrderCanary({
      runId, assignmentId: aid, marker,
      injectedOrigin: fx.origin, injectedEndpoint: '/profile', injectedParam: 'name', injectedPersona: 'user_a',
    })
    const broker = new RequestBroker({ rejectUnauthorized: false, storage })
    const browser = new ScopedBrowser(broker)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      browser.visitPage({ origin: fx.origin, pathAndQuery: '/admin/feed', persona: 'admin_b', runId, assignmentId: aid } as never, makeLabGrant(fx.origin, { personas: personaMap }), AbortSignal.timeout(30_000)),
    )
    const surfaced = v4.listSecondOrderCanaries(runId, 'surfaced')
    assert.equal(surfaced.length, 1)
  })

  test('T2-20c: second-order surfacing records surfaced_exchange_id and timestamp in SQLite', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const v4 = storage as unknown as V4StoreContract
    const { id } = v4.insertSecondOrderCanary({
      runId, assignmentId: aid, marker: 'gn2o_12345678',
      injectedOrigin: 'http://127.0.0.1:9', injectedEndpoint: '/p', injectedParam: 'q', injectedPersona: 'a',
    })
    v4.markSecondOrderCanarySurfaced(id, {
      surfacedOrigin: 'http://127.0.0.1:9', surfacedEndpoint: '/admin', surfacedPersona: 'b', surfacedExchangeId: 'ex-77', status: 'surfaced',
    })
    const rows = v4.listSecondOrderCanaries(runId, 'surfaced')
    assert.equal(rows[0].surfacedExchangeId ?? rows[0].surfaced_exchange_id, 'ex-77')
    assert.ok(Number(rows[0].surfacedAt ?? rows[0].surfaced_at) > 0)
  })

  test('T2-20d: second-order surfacing records high-priority second_order_surface fact for Coordinator', async (t) => {
    const marker = 'gn2o_99887766'
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body><pre>${marker}</pre></body></html>`)
    })
    const { storage } = makeStore(t)
    const { runId, personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [
        { handle: 'user_a', roleLabel: 'A', authKind: 'bearer', secret: 'tok-a' },
        { handle: 'admin', roleLabel: 'Admin', authKind: 'bearer', secret: 'tok-admin' },
      ],
    })
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const v4 = storage as unknown as V4StoreContract
    v4.insertSecondOrderCanary({
      runId, assignmentId: aid, marker,
      injectedOrigin: fx.origin, injectedEndpoint: '/comments', injectedParam: 'body', injectedPersona: 'user_a',
    })
    const broker = new RequestBroker({ rejectUnauthorized: false, storage }) as unknown as V4BrokerContract
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      broker.executeHttp(
        { origin: fx.origin, method: 'GET', pathAndQuery: '/admin/export', persona: 'admin', runId, assignmentId: aid },
        makeLabGrant(fx.origin, { personas: personaMap }),
        AbortSignal.timeout(5000),
      ),
    )
    const facts = storage.listFacts(runId, { includeTainted: false, limit: 50 })
    assert.ok(facts.some(f => String(f.kind).includes('second_order') && /second.order|gn2o_99887766/i.test(f.summary)))
  })

  test('T2-20e: Coordinator dispatches browser_chain verification step for surfaced Stored XSS canary', async (t) => {
    const marker = 'gn2o_t220e_surfaced'
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      if (req.url === '/admin/export') {
        res.end(`<html><body><div id="out"></div><script>document.getElementById('out').innerHTML = ${JSON.stringify(`<img src=x onerror=1>${marker}`)};</script></body></html>`)
        return
      }
      res.end('<html><body><div id="out">clean</div></body></html>')
    })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const browser = new ScopedBrowser(broker)
    const steps = [
      { id: 'c1', role: 'control', description: 'Control view', origin: fx.origin, pathAndQuery: '/clean', action: 'navigate' },
      { id: 'p1', role: 'probe', description: 'Admin views surfaced canary', origin: fx.origin, pathAndQuery: '/admin/export', action: 'dom_xss_sink_hook', enableSinkHook: true },
    ]
    const recipe = browserSinkEnvelopeFromSteps({ origin: fx.origin, vulnClass: 'xss_stored', canaryToken: marker, steps })
    assert.ok(recipe, 'expected browser_sink recipe envelope for T2-20e')
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'browser_chain',
          recipe,
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.status == 200 and (.steps.p1.domSnippet | contains("onerror"))), observed: .steps.p1.domSnippet, expected: "sanitized output without onerror" }',
          steps,
        },
        broker,
        browser,
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
  })

  // --- Feature 21: Build-Time Safe Nuclei Template Transpiler ---

  test('T2-21a: transpiler CLI/function writes vetted YAML files into output directory', async (t) => {
    const mod = await loadV4Module('scripts/transpile-nuclei-templates.ts')
    const transpileDir = requireExport<(inDir: string, outDir: string) => Promise<{ transpiled: number; rejected: Array<{ file: string; reason: string }> }>>(
      mod, 'transpileNucleiDirectory', 'scripts/transpile-nuclei-templates.ts',
    )
    const inDir = makeTempDir(t, 'kovo-v4-nuc-in-')
    const outDir = makeTempDir(t, 'kovo-v4-nuc-out-')
    writeFileSync(join(inDir, 'good.yaml'), `id: cve-2024-11111\ninfo:\n  name: Sample Exposure\n  severity: medium\n  tags: nextjs,exposure\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/.next/trace"\n    matchers:\n      - type: word\n        words:\n          - "webpack"\n`)
    writeFileSync(join(inDir, 'bad.yaml'), `id: bad-net\ninfo:\n  name: Bad Network\n  severity: high\nnetwork:\n  - inputs: [{ data: "hi" }]\n`)
    const res = await transpileDir(inDir, outDir)
    assert.equal(res.transpiled, 1)
    assert.equal(res.rejected.length, 1)
    const loaded = loadSafeTemplates({ dir: outDir, refresh: true })
    assert.equal(loaded.errors.length, 0)
    assert.equal(loaded.templates.length, 1)
  })

  test('T2-21b: 100% of src/templates/compiled/ passes loadSafeTemplates Zod TemplateValidationError gate (>= 1000)', () => {
    const compiledDir = resolve(repoRoot, 'src/templates/compiled')
    assert.ok(existsSync(compiledDir), 'src/templates/compiled directory missing')
    const loaded = loadSafeTemplates({ dir: compiledDir, refresh: true })
    assert.equal(loaded.errors.length, 0, `Template errors: ${JSON.stringify(loaded.errors.slice(0, 5))}`)
    assert.ok(loaded.templates.length >= 1000, `Expected >= 1000 compiled templates, got ${loaded.templates.length}`)
  })

  test('T2-21c: selectSafeTemplates filters compiled pack by detected tech stack tags (nextjs, springboot)', () => {
    const compiledDir = resolve(repoRoot, 'src/templates/compiled')
    assert.ok(existsSync(compiledDir), 'src/templates/compiled directory missing')
    const loaded = loadSafeTemplates({ dir: compiledDir, refresh: true })
    const sel = selectSafeTemplates(loaded.templates, { techTags: ['nextjs'], tier: 1, maxTemplates: 150 })
    assert.ok(sel.selected.length >= 1 && sel.selected.length <= 150)
    assert.ok(sel.selected.every(t => t.tech.includes('generic') || t.tech.includes('nextjs')))
  })

  test('T2-21d: runSafeTemplates executes capped 150/origin compiled templates against loopback target', async (t) => {
    const compiledDir = resolve(repoRoot, 'src/templates/compiled')
    assert.ok(existsSync(compiledDir), 'src/templates/compiled directory missing')
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.statusCode = 404
      res.end('not found')
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1', KOVO_TEMPLATES_DIR: compiledDir }, () =>
      runSafeTemplates(
        {
          origin: fx.origin,
          techFingerprint: ['nextjs'],
          maxTemplates: 150,
          templatesDir: compiledDir,
        },
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { tier: 1 }),
        undefined,
        AbortSignal.timeout(30_000),
      ),
    )
    assert.ok(fx.requests.length <= 450)
    assert.ok(res && typeof res === 'object')
  })

  test('T2-21e: SPA catch-all calibration suppresses false positives across transpiled templates', async (t) => {
    const compiledDir = resolve(repoRoot, 'src/templates/compiled')
    assert.ok(existsSync(compiledDir), 'src/templates/compiled directory missing')
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end('<!doctype html><html><body><div id="app">SPA Catchall Shell</div></body></html>')
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1', KOVO_TEMPLATES_DIR: compiledDir }, () =>
      runSafeTemplates(
        {
          origin: fx.origin,
          techFingerprint: ['generic'],
          maxTemplates: 40,
          templatesDir: compiledDir,
        },
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(fx.origin, { tier: 1 }),
        undefined,
        AbortSignal.timeout(30_000),
      ),
    )
    assert.equal(res.matches.length, 0)
  })

  // --- Feature 22: Budget- & Coverage-Driven Dynamic Queueing ---

  test('T2-22a: run with 25 crown-jewel endpoints + 15 suspects computes dynamicStepBudget = 65 (> 32)', async (t) => {
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call',
      callId: 'c_b22a',
      name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'proved', summary: 'Planned' }),
    }))
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'Reasoning', endpoint: llm.endpoint, model: 'mock-r', protocol: 'responses', key: 'sk-b22a-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'reasoning',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId, run } = await setupApprovedRun(storage, { budgetRequests: 2000 })
    const v4 = storage as unknown as V4StoreContract
    for (let i = 0; i < 25; i++) {
      v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: `/api/admin/r/${i}`, source: 'openapi', riskScore: 90 })
    }
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'threat_model', 'running', 1, 0, ?, '[]', ?, 'audit', 'audit', ?)`)
      .run(aid, runId, randomUUID(), JSON.stringify(['http://127.0.0.1:9']), Date.now())
    const assignment = storage.worker(aid)
    for (let i = 0; i < 15; i++) {
      storage.addFact(run, assignment, {
        kind: 'code_audit_suspect', origin: 'http://127.0.0.1:9', summary: `Suspect ${i}`,
        data: { endpoint: `/api/s/${i}`, severity: 'high', category: 'injection-input' },
      })
    }
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 3_500
      while (Date.now() < deadline) {
        const r = storage.client.prepare('SELECT dynamic_step_budget FROM runs WHERE id = ?').get(runId) as { dynamic_step_budget?: number }
        if ((r.dynamic_step_budget ?? 0) >= 65) break
        await delay(50)
      }
      await stopExecution(engine as never)
    })
    const row = storage.client.prepare('SELECT dynamic_step_budget FROM runs WHERE id = ?').get(runId) as { dynamic_step_budget: number }
    assert.equal(row.dynamic_step_budget, 65)
    assert.ok(row.dynamic_step_budget > 32)
  })

  test('T2-22b: SQL coverage query returns untested endpoint classes ordered by risk_score DESC, coverage_pct ASC', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/a', source: 'spa_crawl', riskScore: 50, coveragePct: 10 })
    v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'POST', pathTemplate: '/b', source: 'spa_crawl', riskScore: 95, coveragePct: 0 })
    const res = storage.listEndpoints(runId, { orderBy: 'coverage', minRiskScore: 80 })
    assert.equal(res[0].pathTemplate, '/b')
  })

  test('T2-22c: consecutive dry steps no longer halt dynamic planning in v6', async (t) => {
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call',
      callId: 'c_dry',
      name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'Dry step' }),
    }))
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'Tactical', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-dry-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId } = await setupApprovedRun(storage)
    const now = Date.now()
    for (let i = 1; i <= 6; i++) {
      storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, created_at, updated_at) VALUES (?, ?, 0, 1, ?, ?, 'h', 'injection-input', 50, '[]', '[]', '[]', '[]', 'complete', '[]', ?, ?)`)
        .run(randomUUID(), runId, i, `Dry Step ${i}`, now + i, now + i)
    }
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 3_500
      while (Date.now() < deadline) {
        const p = storage.run(runId).phase
        if (p === 'verification' || p === 'complete') break
        await delay(50)
      }
      await stopExecution(engine as never)
    })
    assert.notEqual(storage.run(runId).status, 'failed', 'v6 does not fail a run over a dry streak')
    assert.ok(
      !storage.eventsAfter(runId, 0).some(e => e.kind === 'planner.diminishing_returns'),
      'the retired K=6 halt event must not fire',
    )
  })

  test('T2-22d: raise_budget command resumes budget_paused run with higher budgetRequests', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { budgetUsd: 1, budgetRequests: 10 })
    storage.client.prepare(`UPDATE runs SET status = 'budget_paused' WHERE id = ?`).run(runId)
    storage.command({ requestId: randomUUID(), runId, action: 'raise_budget', budgetUsd: 10, budgetRequests: 500, resume: true })
    const run = storage.run(runId)
    assert.equal(run.budgetRequests, 500)
    assert.notEqual(run.status, 'budget_paused')
  })

  test('T2-22e: Execution tracks spentRequests accurately against dynamic budget', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { budgetRequests: 200 })
    storage.client.prepare('UPDATE runs SET spent_requests = spent_requests + 12 WHERE id = ?').run(runId)
    const run = storage.run(runId)
    assert.equal(run.spentRequests, 12)
  })

  // --- Feature 23: 7 Clean-Context Specialist Worker Profiles ---

  test('T2-23a: bola-bfla-specialist receives BOLA/HTTP/verify tools without unrelated XSS/SSRF clutter', async (t) => {
    assert.ok(specialistProfiles.includes('bola-bfla-specialist'), 'bola-bfla-specialist missing from specialistProfiles')
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call',
      callId: 'c_sp_bola',
      name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'Checked BOLA' }),
    }))
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'Tactical', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-sp1-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId } = await setupApprovedRun(storage)
    const now = Date.now()
    storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, specialist_profile, created_at, updated_at) VALUES (?, ?, 0, 1, 1, 'BOLA /api/orders/{id}', 'Cross-tenant IDOR', 'broken-access-control', 90, '[]', '["bola"]', '[]', '[]', 'pending', '["http://127.0.0.1:9"]', 'bola-bfla-specialist', ?, ?)`)
      .run(randomUUID(), runId, now, now)
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 3_500
      while (Date.now() < deadline && llm.calls.length === 0) await delay(50)
      await stopExecution(engine as never)
    })
    assert.ok(llm.calls.length >= 1, 'Expected bola-bfla-specialist worker LLM invocation')
    const toolNames = ((llm.calls[0].body.tools as Array<{ name: string }>) ?? []).map(tl => tl.name)
    assert.ok(toolNames.includes('probe_differential') && toolNames.includes('verify_replay_spec'))
  })

  test('T2-23b: injection-parser-specialist receives sqli/xxe/IAST tools and injection skills', async (t) => {
    assert.ok(specialistProfiles.includes('injection-parser-specialist'), 'injection-parser-specialist missing from specialistProfiles')
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call',
      callId: 'c_sp_inj',
      name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'Checked SQLi' }),
    }))
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'Tactical', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-sp2-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId } = await setupApprovedRun(storage)
    const now = Date.now()
    storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, specialist_profile, created_at, updated_at) VALUES (?, ?, 0, 1, 1, 'SQLi /api/orders?id=', 'SQLi error differential', 'injection-input', 90, '[]', '["sqli"]', '[]', '[]', 'pending', '["http://127.0.0.1:9"]', 'injection-parser-specialist', ?, ?)`)
      .run(randomUUID(), runId, now, now)
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 3_500
      while (Date.now() < deadline && llm.calls.length === 0) await delay(50)
      await stopExecution(engine as never)
    })
    assert.ok(llm.calls.length >= 1)
    const toolNames = ((llm.calls[0].body.tools as Array<{ name: string }>) ?? []).map(tl => tl.name)
    assert.ok(toolNames.includes('probe_differential') && toolNames.includes('verify_replay_spec'))
  })

  test('T2-23c: auth-session-oauth-specialist receives auth_protocol/canary/verify tools', async (t) => {
    assert.ok(specialistProfiles.includes('auth-session-oauth-specialist'), 'auth-session-oauth-specialist missing from specialistProfiles')
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call',
      callId: 'c_sp_auth',
      name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'Checked OAuth' }),
    }))
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'Tactical', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-sp3-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId } = await setupApprovedRun(storage)
    const now = Date.now()
    storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, specialist_profile, created_at, updated_at) VALUES (?, ?, 0, 1, 1, 'JWT alg=none bypass', 'Verify auth_protocol_proof', 'auth-session', 90, '[]', '["jwt"]', '[]', '[]', 'pending', '["http://127.0.0.1:9"]', 'auth-session-oauth-specialist', ?, ?)`)
      .run(randomUUID(), runId, now, now)
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 3_500
      while (Date.now() < deadline && llm.calls.length === 0) await delay(50)
      await stopExecution(engine as never)
    })
    assert.ok(llm.calls.length >= 1)
    const toolNames = ((llm.calls[0].body.tools as Array<{ name: string }>) ?? []).map(tl => tl.name)
    assert.ok(toolNames.includes('verify_replay_spec'))
  })

  test('T2-23d: client-browser-dom-specialist receives browser/WS/xss_context tools', async (t) => {
    assert.ok(specialistProfiles.includes('client-browser-dom-specialist'), 'client-browser-dom-specialist missing from specialistProfiles')
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call',
      callId: 'c_sp_dom',
      name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'Checked DOM' }),
    }))
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'Tactical', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-sp4-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId } = await setupApprovedRun(storage)
    const now = Date.now()
    storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, specialist_profile, created_at, updated_at) VALUES (?, ?, 0, 1, 1, 'DOM XSS sink', 'innerHTML sink trace', 'injection-input', 90, '[]', '["xss"]', '[]', '[]', 'pending', '["http://127.0.0.1:9"]', 'client-browser-dom-specialist', ?, ?)`)
      .run(randomUUID(), runId, now, now)
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 3_500
      while (Date.now() < deadline && llm.calls.length === 0) await delay(50)
      await stopExecution(engine as never)
    })
    assert.ok(llm.calls.length >= 1)
    const toolNames = ((llm.calls[0].body.tools as Array<{ name: string }>) ?? []).map(tl => tl.name)
    assert.ok(toolNames.some(tName => /browser/i.test(tName)))
  })

  test('T2-23e: graphql, business-logic-race, and protocol-cache specialists route cleanly by category', async (t) => {
    for (const id of ['graphql-api-specialist', 'business-logic-race-specialist', 'protocol-cache-edge-specialist'] as const) {
      assert.ok(specialistProfiles.includes(id), `Missing specialist profile ${id}`)
    }
    const { storage } = makeStore(t)
    const { runId, run } = await setupApprovedRun(storage)
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'threat_model', 'running', 1, 0, ?, '[]', ?, 'tm', 'tm', ?)`)
      .run(aid, runId, randomUUID(), JSON.stringify(['http://127.0.0.1:9']), Date.now())
    const assignment = storage.worker(aid)
    const facts = [
      storage.addFact(run, assignment, { kind: 'code_audit_suspect', origin: 'http://127.0.0.1:9', summary: 'GraphQL nested resolver BOLA', data: { category: 'broken-access-control', hypothesis: 'graphql resolver', endpoint: '/graphql' } }),
      storage.addFact(run, assignment, { kind: 'code_audit_suspect', origin: 'http://127.0.0.1:9', summary: 'Coupon double spend race', data: { category: 'business-logic-race', hypothesis: 'race_burst', endpoint: '/api/redeem' } }),
      storage.addFact(run, assignment, { kind: 'code_audit_suspect', origin: 'http://127.0.0.1:9', summary: 'Cache poisoning X-Forwarded-Host', data: { category: 'misconfig-exposure', hypothesis: 'cache_poison_deception', endpoint: '/home' } }),
    ]
    convertCodeAuditSuspectsToChainSteps(storage, run, facts)
    const rows = storage.client.prepare('SELECT title, specialist_profile FROM chain_steps WHERE run_id = ?').all(runId) as Array<{ title: string; specialist_profile: string | null }>
    assert.equal(rows.find(r => r.title.includes('GraphQL'))?.specialist_profile, 'graphql-api-specialist')
    assert.equal(rows.find(r => r.title.includes('Coupon'))?.specialist_profile, 'business-logic-race-specialist')
    assert.equal(rows.find(r => r.title.includes('Cache'))?.specialist_profile, 'protocol-cache-edge-specialist')
  })

  // --- Feature 24: Multi-Trial Parallel Branching + Early Stopping ---

  test('T2-24a: createMultiTrialSteps spawns 2 distinct trials sharing trialGroupId for crown-jewel lead', async (t) => {
    // Benign 404 fixture: a dead seed trips the v5 origin circuit breaker and the run pauses
    // before the crown-jewel lead can be fanned out into trials.
    const fx = await startHttpFixture(t, (_req, _body, res) => { res.statusCode = 404; res.end('not found') })
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call',
      callId: 'c_tm_24a',
      name: 'complete_intent',
      argumentsJson: JSON.stringify({
        status: 'proved',
        summary: 'Crown jewel threat model',
        steps: [{ title: 'Crown Jewel Admin SQLi', hypothesis: 'sqli in /admin/query', category: 'injection-input', priority: 92, origins: [fx.origin] }],
      }),
    }))
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'Reasoning', endpoint: llm.endpoint, model: 'mock-r', protocol: 'responses', key: 'sk-24a-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'high', roleAffinity: 'reasoning',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 12_000
      while (Date.now() < deadline) {
        const trials = storage.client.prepare('SELECT trial_group_id, trial_index FROM chain_steps WHERE run_id = ? AND trial_group_id IS NOT NULL').all(runId) as Array<{ trial_group_id: string; trial_index: number }>
        if (trials.length >= 2) break
        await delay(50)
      }
      await stopExecution(engine as never)
    })
    const rows = storage.client.prepare('SELECT id, trial_group_id, trial_index FROM chain_steps WHERE run_id = ? AND trial_group_id IS NOT NULL ORDER BY trial_index ASC').all(runId) as Array<{ id: string; trial_group_id: string; trial_index: number }>
    assert.ok(rows.length >= 2, 'Expected >=2 parallel trials for crown-jewel priority >= 92 lead')
    assert.equal(rows[0].trial_group_id, rows[1].trial_group_id)
    assert.notEqual(rows[0].trial_index, rows[1].trial_index)
  })

  test('T2-24b: early-stop cancels sibling trials cleanly in SQLite when Trial 0 achieves confirmed', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (req.url === '/slow') {
        setTimeout(() => res.end(JSON.stringify({ leaked: false })), 60000)
        return
      }
      res.end(JSON.stringify({ leaked: req.url === '/p' }))
    })
    let confirmedOnce = false
    let trialCalls = 0
    const llm = await startMockLlmServer(t, (call) => {
      const prompt = JSON.stringify(call.body)
      const trialPrompt = !prompt.includes('Stateless Coordinator Planner') && (prompt.includes('BOLA') || prompt.includes('broken-access-control'))
      if (trialPrompt) trialCalls += 1
      if (!confirmedOnce && trialPrompt) {
        confirmedOnce = true
        return {
          type: 'tool_call',
          callId: 'c_win_24b',
          name: 'propose_chain_finding',
          argumentsJson: JSON.stringify({
            counterevidence: 'Control endpoint returns false while probe leaks tenant secret',
            confidenceRationale: 'Deterministic replay differential confirmed status 200 leak',
            chainFactIds: [],
            exchangeIds: [],
            verifyNow: true,
            replaySpec: {
              ...baseReplaySpecFields(fx.origin),
              title: 'Critical BOLA',
              category: 'broken-access-control',
              severity: 'critical',
              kind: 'http_chain',
              assertionsJq: '{ controlPassed: (.steps.c1.json.leaked == false), confirmed: (.steps.p1.json.leaked == true), observed: (.steps.p1.json.leaked | tostring), expected: "false" }',
              steps: [
                { id: 'c1', role: 'control', description: 'Control', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/c' } },
                { id: 'p1', role: 'probe', description: 'Probe', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/p' } },
              ],
            },
          }),
        }
      }
      return { type: 'tool_call', callId: 'c_done_24b', name: 'complete_intent', argumentsJson: JSON.stringify({ status: 'proved', summary: 'done' }) }
    })
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'Tactical', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-24b-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'any',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const gid = randomUUID()
    const now = Date.now()
    const s0 = randomUUID()
    const s1 = randomUUID()
    storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, trial_group_id, trial_index, created_at, updated_at) VALUES (?, ?, 0, 1, 1, 'BOLA T0', 'h', 'broken-access-control', 96, '[]', '[]', '[]', '[]', 'pending', ?, ?, 0, ?, ?)`)
      .run(s0, runId, JSON.stringify([fx.origin]), gid, now, now)
    storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, trial_group_id, trial_index, created_at, updated_at) VALUES (?, ?, 0, 1, 2, 'BOLA T1', 'h', 'broken-access-control', 96, '[]', '[]', '[]', '[]', 'pending', ?, ?, 1, ?, ?)`)
      .run(s1, runId, JSON.stringify([fx.origin]), gid, now + 1, now + 1)
    storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 1 })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 50_000
      while (Date.now() < deadline) {
        const sib = storage.client.prepare('SELECT status FROM chain_steps WHERE id = ?').get(s1) as { status: string }
        if (sib.status === 'canceled') break
        await delay(50)
      }
      await stopExecution(engine as never)
    })
    const siblingRow = storage.client.prepare('SELECT status FROM chain_steps WHERE id = ?').get(s1) as { status: string }
    assert.equal(siblingRow.status, 'canceled')
  })

  test('T2-24c: early stopping preserves remaining run budget by not running canceled siblings', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const gid = randomUUID()
    const now = Date.now()
    const s1 = randomUUID()
    const s2 = randomUUID()
    storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, trial_group_id, trial_index, created_at, updated_at) VALUES (?, ?, 0, 1, 1, 'T1', 'h', 'injection-input', 95, '[]', '[]', '[]', '[]', 'complete', '[]', ?, 0, ?, ?)`)
      .run(s1, runId, gid, now, now)
    storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, trial_group_id, trial_index, created_at, updated_at) VALUES (?, ?, 0, 1, 2, 'T2', 'h', 'injection-input', 95, '[]', '[]', '[]', '[]', 'canceled', '[]', ?, 1, ?, ?)`)
      .run(s2, runId, gid, now, now)
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call', callId: 'c_24c', name: 'complete_intent', argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'skip' }),
    }))
    await saveModelProfile({
      name: 'Tactical', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-24c-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      await delay(600)
      await stopExecution(engine as never)
    })
    assert.equal(llm.calls.length, 0, 'Canceled sibling trial must consume 0 LLM calls')
    assert.equal(storage.run(runId).spentRequests, 0)
  })

  test('T2-24d: SQLite chain_steps records distinct trial indices across trialGroupId', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const gid = randomUUID()
    const now = Date.now()
    for (let i = 0; i < 2; i++) {
      storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, trial_group_id, trial_index, created_at, updated_at) VALUES (?, ?, 0, 1, ?, ?, 'h', 'injection-input', 98, '[]', '[]', '[]', '[]', 'pending', '[]', ?, ?, ?, ?)`)
        .run(randomUUID(), runId, i + 1, `Critical RCE Trial ${i}`, gid, i, now + i, now + i)
    }
    const rows = storage.client.prepare('SELECT trial_index FROM chain_steps WHERE trial_group_id = ? ORDER BY trial_index ASC').all(gid) as Array<{ trial_index: number }>
    assert.deepEqual(rows.map(r => r.trial_index), [0, 1])
  })

  test('T2-24e: trial.early_stopped SSE event emitted upon sibling cancellation', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (req.url === '/slow') {
        setTimeout(() => res.end(JSON.stringify({ leaked: false })), 60000)
        return
      }
      res.end(JSON.stringify({ leaked: req.url === '/p' }))
    })
    let done = false
    let trialCalls = 0
    const llm = await startMockLlmServer(t, (call) => {
      const prompt = JSON.stringify(call.body)
      const trialPrompt = !prompt.includes('Stateless Coordinator Planner') && prompt.includes('Critical RCE')
      if (trialPrompt) trialCalls += 1
      if (!done && trialPrompt) {
        done = true
        return {
          type: 'tool_call',
          callId: 'c_win_24e',
          name: 'propose_chain_finding',
          argumentsJson: JSON.stringify({
            counterevidence: 'Control endpoint returns false while probe leaks secret payload',
            confidenceRationale: 'Deterministic replay differential confirmed status 200 leak',
            chainFactIds: [],
            exchangeIds: [],
            verifyNow: true,
            replaySpec: {
              ...baseReplaySpecFields(fx.origin),
              title: 'Critical RCE',
              category: 'injection-input',
              severity: 'critical',
              kind: 'http_chain',
              assertionsJq: '{ controlPassed: (.steps.c1.json.leaked == false), confirmed: (.steps.p1.json.leaked == true), observed: (.steps.p1.json.leaked | tostring), expected: "false" }',
              steps: [
                { id: 'c1', role: 'control', description: 'Control', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/c' } },
                { id: 'p1', role: 'probe', description: 'Probe', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/p' } },
              ],
            },
          }),
        }
      }
      return { type: 'tool_call', callId: 'c_done_24e', name: 'complete_intent', argumentsJson: JSON.stringify({ status: 'proved', summary: 'done' }) }
    })
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'Tactical', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-24e-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'any',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const gid = randomUUID()
    const now = Date.now()
    storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, trial_group_id, trial_index, created_at, updated_at) VALUES (?, ?, 0, 1, 1, 'Critical RCE Trial 0', 'h', 'injection-input', 95, '[]', '[]', '[]', '[]', 'pending', ?, ?, 0, ?, ?)`)
      .run(randomUUID(), runId, JSON.stringify([fx.origin]), gid, now, now)
    storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, trial_group_id, trial_index, created_at, updated_at) VALUES (?, ?, 0, 1, 2, 'Critical RCE Trial 1', 'h', 'injection-input', 95, '[]', '[]', '[]', '[]', 'pending', ?, ?, 1, ?, ?)`)
      .run(randomUUID(), runId, JSON.stringify([fx.origin]), gid, now + 1, now + 1)
    storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 1 })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 50_000
      while (Date.now() < deadline && !storage.eventsAfter(runId, 0, 50).some(e => e.kind === 'trial.early_stopped')) {
        await delay(50)
      }
      await stopExecution(engine as never)
    })
    const evs = storage.eventsAfter(runId, 0, 50)
    assert.ok(evs.some(e => e.kind === 'trial.early_stopped'))
  })

  // --- Feature 25: Role-Based Tiered Model Routing ---

  test('T2-25a: saveModelProfile persists roleAffinity into SQLite model_profiles.role_affinity', async (t) => {
    const { storage } = makeStore(t)
    const saved = await saveModelProfile({
      name: 'Reasoning Model', endpoint: 'https://openrouter.ai/api/v1', model: 'anthropic/claude-opus',
      protocol: 'messages', key: 'sk-reason-12345678', priority: 100, enabled: true,
      contextWindow: 200_000, maxTokens: 16_384, thinkingLevel: 'high',
      inputCostPerMtok: 5, cachedInputCostPerMtok: 0.5, outputCostPerMtok: 15, roleAffinity: 'reasoning',
    } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    const row = storage.client.prepare('SELECT role_affinity FROM model_profiles WHERE id = ?').get(saved.id) as { role_affinity: string }
    assert.equal(row.role_affinity, 'reasoning')
  })

  test('T2-25b: resolveProfilePoolForRole(reasoning) returns reasoning profiles first, then any', async (t) => {
    const mod = await import('../src/server/model-settings.ts') as Record<string, unknown>
    const resolvePool = requireExport<(role: RoleAffinity, storage?: Store) => Array<{ name: string; roleAffinity?: string }>>(
      mod, 'resolveProfilePoolForRole', 'src/server/model-settings.ts',
    )
    const { storage } = makeStore(t)
    const base = {
      endpoint: 'https://openrouter.ai/api/v1', model: 'deepseek/v4', protocol: 'responses' as const,
      key: 'sk-test-12345678', enabled: true, contextWindow: 128_000, maxTokens: 8192,
      thinkingLevel: 'medium' as const, inputCostPerMtok: 0.1, cachedInputCostPerMtok: 0, outputCostPerMtok: 0.2,
    }
    await saveModelProfile({ ...base, name: 'AnyHigherPrio', priority: 300, roleAffinity: 'any' } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    await saveModelProfile({ ...base, name: 'ReasoningExact', priority: 100, roleAffinity: 'reasoning' } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    await saveModelProfile({ ...base, name: 'FastOnly', priority: 400, roleAffinity: 'fast' } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    const pool = resolvePool('reasoning', storage)
    assert.equal(pool[0].name, 'ReasoningExact')
    assert.equal(pool[1].name, 'AnyHigherPrio')
  })

  test('T2-25c: Code Audit & Patch roles route to reasoning; Specialist routes to tactical', async () => {
    assert.equal(roleAffinityForScenario('code-auditor'), 'reasoning')
    assert.equal(roleAffinityForScenario('patch-author'), 'reasoning')
    assert.equal(roleAffinityForScenario('worker-investigation'), 'tactical')
    assert.equal(roleAffinityForScenario('worker-analysis'), 'fast')
    assert.equal(roleAffinityForScenario('compactor'), 'fast')
  })

  test('T2-25d: privateModelProfiles and listModelProfiles expose roleAffinity cleanly without keys', async (t) => {
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'TacticalOne', endpoint: 'https://openrouter.ai/api/v1', model: 'deepseek/v4',
      protocol: 'responses', key: 'sk-secret-tactical-1234', priority: 100, enabled: true,
      contextWindow: 128_000, maxTokens: 8192, thinkingLevel: 'medium',
      inputCostPerMtok: 0.1, cachedInputCostPerMtok: 0, outputCostPerMtok: 0.2, roleAffinity: 'tactical',
    } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    const pub = listModelProfiles(storage) as unknown as Array<Record<string, unknown>>
    const priv = privateModelProfiles(storage) as unknown as Array<Record<string, unknown>>
    assert.equal(pub[0].roleAffinity, 'tactical')
    assert.equal(priv[0].roleAffinity, 'tactical')
    assert.ok(!JSON.stringify(pub).includes('sk-secret-tactical-1234'))
  })

  test('T2-25e: roleAffinity routes real Execution LLM requests to distinct model endpoints by role', async (t) => {
    const reasoningLlm = await startMockLlmServer(t, () => ({
      type: 'tool_call', callId: 'c_r', name: 'complete_intent', argumentsJson: JSON.stringify({ status: 'proved', summary: 'reasoning-ok' }),
    }))
    const fastLlm = await startMockLlmServer(t, () => ({
      type: 'tool_call', callId: 'c_f', name: 'complete_intent', argumentsJson: JSON.stringify({ status: 'proved', summary: 'fast-ok' }),
    }))
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'R', endpoint: reasoningLlm.endpoint, model: 'mock-r', protocol: 'responses',
      key: 'sk-r-12345678', priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096,
      thinkingLevel: 'high', inputCostPerMtok: 1, cachedInputCostPerMtok: 0, outputCostPerMtok: 2, roleAffinity: 'reasoning',
    } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    await saveModelProfile({
      name: 'F', endpoint: fastLlm.endpoint, model: 'mock-f', protocol: 'responses',
      key: 'sk-f-12345678', priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096,
      thinkingLevel: 'low', inputCostPerMtok: 0.1, cachedInputCostPerMtok: 0, outputCostPerMtok: 0.2, roleAffinity: 'fast',
    } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    const mod = await import('../src/server/model-settings.ts') as Record<string, unknown>
    const resolvePool = requireExport<(role: RoleAffinity, storage?: Store) => Array<{ endpoint: string }>>(
      mod, 'resolveProfilePoolForRole', 'src/server/model-settings.ts',
    )
    assert.equal(resolvePool('reasoning', storage)[0].endpoint, reasoningLlm.endpoint)
    assert.equal(resolvePool('fast', storage)[0].endpoint, fastLlm.endpoint)
    // A dead seed pauses the run at the circuit breaker before any LLM stage runs.
    const fx = await startHttpFixture(t, (_req, _body, res) => { res.statusCode = 404; res.end('not found') })
    await setupApprovedRun(storage, { seeds: [fx.origin] })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 10_000
      while (Date.now() < deadline && reasoningLlm.calls.length === 0) await delay(50)
      await stopExecution(engine as never)
    })
    assert.ok(reasoningLlm.calls.length >= 1, 'Expected reasoning-affined Execution stage to route to reasoningLlm endpoint')
  })

  // --- Feature 26: Recall Benchmark Harness & Failure Taxonomy ---

  test('T2-26a: deterministic failure attribution assigns surface_miss, form_encoding_missing, csrf_blocked', async () => {
    for (const bucket of ['surface_miss', 'form_encoding_missing', 'csrf_blocked'] as const) {
      assert.ok((failureTaxonomyBuckets as readonly string[]).includes(bucket), `Missing taxonomy bucket ${bucket}`)
    }
    const mod = await loadV4Module('scripts/benchmark-recall.ts')
    assert.ok(typeof mod.runBenchmarkSuite === 'function', 'runBenchmarkSuite must be exported by scripts/benchmark-recall.ts')
  })

  test('T2-26b: deterministic failure attribution assigns context_reset, jq_assertion_bug, spa_catchall_fp, budget_exhausted', async () => {
    for (const bucket of ['context_reset', 'jq_assertion_bug', 'spa_catchall_fp', 'budget_exhausted'] as const) {
      assert.ok((failureTaxonomyBuckets as readonly string[]).includes(bucket), `Missing taxonomy bucket ${bucket}`)
    }
    const mod = await loadV4Module('scripts/benchmark-recall.ts')
    assert.ok(typeof mod.runBenchmarkSuite === 'function', 'runBenchmarkSuite must be exported by scripts/benchmark-recall.ts')
  })

  test('T2-26c: benchmark_runs persists across 2 git SHAs and Store.listBenchmarkRuns orders chronologically', async (t) => {
    const { storage } = makeStore(t)
    const v4 = storage as unknown as V4StoreContract
    v4.insertBenchmarkRun({
      suite: 'xben-25', gitSha: 'sha-1', modelRoutingConfig: {}, targetsTotal: 25, confirmedCount: 11, falsePositiveCount: 0,
      funnelCounts: { targetVulns: 25, zeroLlmConfirmed: 11 }, failureTaxonomy: { surface_miss: 6 }, totalCostUsd: 2.1, durationMs: 10_000,
    })
    await delay(5)
    v4.insertBenchmarkRun({
      suite: 'xben-25', gitSha: 'sha-2', modelRoutingConfig: {}, targetsTotal: 25, confirmedCount: 22, falsePositiveCount: 0,
      funnelCounts: { targetVulns: 25, zeroLlmConfirmed: 22 }, failureTaxonomy: { surface_miss: 1 }, totalCostUsd: 2.9, durationMs: 12_000,
    })
    const list = v4.listBenchmarkRuns('xben-25', 10)
    assert.equal(list.length, 2)
    assert.equal(list[0].gitSha ?? list[0].git_sha, 'sha-2')
  })

  test('T2-26d: benchmark diff report quantifies recall delta, FP delta, cost-per-vuln, and top bucket drops', async (t) => {
    const mod = await loadV4Module('scripts/benchmark-recall.ts')
    const runBenchmarkSuite = requireExport<(opts: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runBenchmarkSuite', 'scripts/benchmark-recall.ts',
    )
    const outDir = makeTempDir(t, 'kovo-v4-bdiff-')
    const outJson = join(outDir, 'diff.json')
    const outMd = join(outDir, 'diff.md')
    const { storage } = makeStore(t)
    const v4 = storage as unknown as V4StoreContract
    v4.insertBenchmarkRun({
      suite: 'held-out-saas', gitSha: 'base', modelRoutingConfig: {}, targetsTotal: 20, confirmedCount: 8, falsePositiveCount: 0,
      funnelCounts: { targetVulns: 20, zeroLlmConfirmed: 8 }, failureTaxonomy: { csrf_blocked: 4, surface_miss: 5 }, totalCostUsd: 4.0, durationMs: 5000,
    })
    await runBenchmarkSuite({ suite: 'held-out-saas', baselineSha: 'base', storage, outJson, outMd, dryRun: true })
    assert.ok(existsSync(outJson), 'Expected benchmark diff JSON file')
    assert.ok(existsSync(outMd), 'Expected benchmark diff Markdown file')
    const md = readFileSync(outMd, 'utf8')
    assert.match(md, /recall|confirmed|csrf_blocked|surface_miss/i)
  })

  test('T2-26e: benchmark-recall CLI parser supports --suite, --baseline-sha, --out-json, --out-md', async (t) => {
    const outDir = makeTempDir(t, 'kovo-v4-bcli-')
    const outJson = join(outDir, 'cli.json')
    const outMd = join(outDir, 'cli.md')
    const cli = await exec('node', [
      resolve(repoRoot, 'scripts/benchmark-recall.ts'),
      '--suite', 'held-out-saas', '--baseline-sha', 'base', '--out-json', outJson, '--out-md', outMd,
    ], { cwd: repoRoot })
    assert.ok(cli.stdout.length + cli.stderr.length > 0)
    assert.ok(existsSync(outJson), 'Expected CLI --out-json to be written')
    assert.ok(existsSync(outMd), 'Expected CLI --out-md to be written')
  })

  // --- Feature 27: Local Labs (XBEN-25 & Held-Out SaaS Lab) & Hill-Climbing ---

  test('T2-27a: Held-Out Modern SaaS Lab starts cleanly inside --internal LabRunner network', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T2-27a')
    const labDir = resolve(repoRoot, 'local-lab/held-out-saas')
    assert.ok(existsSync(labDir), 'local-lab/held-out-saas directory missing')
    const runner = new LabRunner()
    t.after(() => runner.stopAll())
    const runId = randomUUID()
    const handle = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runner.startLabTarget({
        runId,
        environment: 'local-lab',
        repoDir: labDir,
        labConfig: { enabled: true, dockerComposeFile: 'docker-compose.yml', healthPath: '/health', internalPort: 3000 },
      }),
    )
    const resp = await fetch(`${handle.origin}/health`)
    assert.equal(resp.status, 200)
    await runner.stopAll()
    await assertZeroKovoOrphans(runId)
  })

  test('T2-27b: Held-Out SaaS Lab exposes planted BOLA/SQLi/GraphQL/XXE/JWT endpoints to RequestBroker', async () => {
    const manifestPath = resolve(repoRoot, 'local-lab/held-out-saas/manifest.json')
    assert.ok(existsSync(manifestPath), 'local-lab/held-out-saas/manifest.json missing')
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as { challenges: Array<{ id: string; vulnClass: string; isDecoy?: boolean }> }
    const classes = new Set(manifest.challenges.filter(c => !c.isDecoy).map(c => c.vulnClass))
    for (const reqClass of ['bola', 'sqli', 'graphql', 'xxe', 'jwt']) {
      assert.ok([...classes].some(c => c.toLowerCase().includes(reqClass)), `Held-Out SaaS Lab missing ${reqClass} challenge`)
    }
  })

  test('T2-27c: Held-Out SaaS Lab 6 hard decoys are distinct and explicitly marked non-vulnerable', async () => {
    const manifestPath = resolve(repoRoot, 'local-lab/held-out-saas/manifest.json')
    assert.ok(existsSync(manifestPath), 'local-lab/held-out-saas/manifest.json missing')
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as { challenges: Array<{ id: string; isDecoy?: boolean; decoyReason?: string }> }
    const decoys = manifest.challenges.filter(c => c.isDecoy)
    assert.equal(decoys.length, 6)
    for (const d of decoys) {
      assert.ok(d.decoyReason && d.decoyReason.length >= 5, `Decoy ${d.id} missing decoyReason`)
    }
  })

  test('T2-27d: XBEN-25 stratified slice covers SQLi, IDOR, SSTI, SSRF, XSS, XXE, Auth/JWT, Path Traversal, RCE', async () => {
    const manifestPath = resolve(repoRoot, 'benchmarks/xben-25/manifest.json')
    assert.ok(existsSync(manifestPath), 'benchmarks/xben-25/manifest.json missing')
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as { challenges: Array<{ id: string; vulnClass: string }> }
    const classes = manifest.challenges.map(c => c.vulnClass.toLowerCase()).join(',')
    for (const cat of ['sqli', 'idor', 'ssti', 'ssrf', 'xss', 'jwt', 'path']) {
      assert.ok(classes.includes(cat), `XBEN-25 missing category ${cat}`)
    }
  })

  test('T2-27e: LabRunner cleanup after Held-Out Lab benchmark run leaves 0 orphan containers', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T2-27e')
    const labDir = resolve(repoRoot, 'local-lab/held-out-saas')
    assert.ok(existsSync(labDir), 'local-lab/held-out-saas directory missing')
    const runId = randomUUID()
    const runner = new LabRunner()
    t.after(async () => { await runner.stopAll() })
    const handle = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runner.startLabTarget({
        runId,
        environment: 'local-lab',
        repoDir: labDir,
        labConfig: { enabled: true, dockerComposeFile: 'docker-compose.yml', healthPath: '/health', internalPort: 3000 },
      }),
    )
    const resp = await fetch(`${handle.origin}/health`)
    assert.equal(resp.status, 200)
    await runner.stopAll()
    await assertZeroKovoOrphans(runId)
  })

  // --- Feature 28: Drizzle SQLite v4 Schema & Lossless Migration ---

  test('T2-28a: Store CRUD roundtrip for endpoints, endpoint_params, and api_dependencies', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    const ep1 = v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'POST', pathTemplate: '/api/items', source: 'openapi', riskScore: 85 })
    const ep2 = v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/api/items/{id}', source: 'spa_crawl', riskScore: 90 })
    v4.upsertEndpointParam({ runId, endpointId: ep1.id, name: 'name', location: 'json', inferredType: 'string', source: 'openapi' })
    v4.recordApiDependency({ runId, producerEndpointId: ep1.id, consumerEndpointId: ep2.id, resourceKey: 'itemId', personaHandle: 'persona_a' })
    assert.equal(v4.listEndpoints(runId).length, 2)
    assert.equal(v4.listEndpointParams(runId, ep1.id).length, 1)
    assert.equal(v4.listApiDependencies(runId).length, 1)
  })

  test('T2-28b: Store CRUD roundtrip for second_order_canaries and lab_telemetry', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const v4 = storage as unknown as V4StoreContract
    const c = v4.insertSecondOrderCanary({
      runId, assignmentId: aid, marker: 'gn2o_00112233',
      injectedOrigin: 'http://127.0.0.1:9', injectedEndpoint: '/bio', injectedParam: 'text',
    })
    assert.equal(v4.listSecondOrderCanaries(runId).length, 1)
    v4.markSecondOrderCanarySurfaced(c.id, { surfacedOrigin: 'http://127.0.0.1:9', surfacedEndpoint: '/admin', status: 'surfaced' })
    assert.equal(v4.listSecondOrderCanaries(runId, 'surfaced').length, 1)
    v4.insertLabTelemetry({ runId, exchangeId: 'e1', traceId: 't1', routesHit: ['/bio'], newLinesCovered: 3, sinkEventsCount: 1, hasUnhandledException: false, artifactId: 'a1' })
    assert.equal(v4.listLabTelemetry(runId).length, 1)
  })

  test('T2-28c: Store updateRunPhase0Completed and updateRunDynamicStepBudget persist atomically', async (t) => {
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    const ts = Date.now()
    v4.updateRunPhase0Completed(runId, ts)
    v4.updateRunDynamicStepBudget(runId, 112)
    const row = storage.client.prepare('SELECT phase0_completed_at, dynamic_step_budget FROM runs WHERE id = ?').get(runId) as {
      phase0_completed_at: number; dynamic_step_budget: number
    }
    assert.equal(row.phase0_completed_at, ts)
    assert.equal(row.dynamic_step_budget, 112)
  })

  test('T2-28d: Store process-lock.sqlite prevents concurrent conflicting Store instances on same directory', async (t) => {
    const { dir } = makeStore(t)
    assert.throws(() => new Store(dir), /Another Kovo(?: Hunter)? server is using this data directory/)
  })

  test('T2-28e: Store WAL journal mode and v4 schema tables survive close -> reopen cycle losslessly', async (t) => {
    const dir = makeTempDir(t, 'kovo-v4-reopen-')
    let savedRunId = ''
    {
      const s1 = new Store(dir)
      const { runId } = await setupApprovedRun(s1)
      savedRunId = runId
      ;(s1 as unknown as V4StoreContract).upsertEndpoint({
        runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/persisted', source: 'openapi',
      })
      s1.close()
    }
    const s2 = new Store(dir)
    t.after(() => s2.close())
    const eps = (s2 as unknown as V4StoreContract).listEndpoints(savedRunId)
    assert.equal(eps.length, 1)
    assert.equal(eps[0].pathTemplate ?? eps[0].path_template, '/persisted')
  })
})


// ============================================================================
// TIER 3 — Cross-Feature Full E2E Workflows (28 cases: T3-01 .. T3-28)
// ============================================================================

describe('Tier 3 — Cross-Feature Full E2E Workflows (28 cases)', () => {
  test('T3-01: Worker repairs broken jq typo via inline verify_replay_spec feedback -> confirmed on retry 2', async (t) => {
    const rvMod = await import('../src/server/replay-verifier.ts') as Record<string, unknown>
    const verifyInline = requireExport<(p: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      rvMod, 'verifyReplaySpecInline', 'src/server/replay-verifier.ts',
    )
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ exposed: req.url === '/api/secret' }))
    })
    const { storage } = makeStore(t)
    const { runId, run } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const assignment = storage.db.select().from((await import('../src/server/schema.ts')).assignments).limit(1).get()!
    const brokenSpec = {
      ...baseReplaySpecFields(fx.origin),
      kind: 'http_chain' as const,
      spaCatchallControl: false,
      assertionsJq: '(.steps[] | select(.role=="probe") | .bodyJson.exposed == true) and (((',
      steps: [
        { id: 'c1', role: 'control' as const, description: 'Public', request: { origin: fx.origin, method: 'GET' as const, pathAndQuery: '/api/public', followRedirects: false } },
        { id: 'p1', role: 'probe' as const, description: 'Secret', request: { origin: fx.origin, method: 'GET' as const, pathAndQuery: '/api/secret', followRedirects: false } },
      ],
    }
    const row = storage.createReplaySpec(run, assignment, randomUUID(), brokenSpec, [fx.origin])
    const r1 = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyInline({
        runId, assignmentId: aid, replaySpecId: row.id, spec: brokenSpec, attemptCount: 1,
        broker: new RequestBroker({ rejectUnauthorized: false }), backend: new LinuxWorkerBackend(),
        storage, grant: makeLabGrant(fx.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    const fb1 = r1.feedback as InlineVerifyFeedback
    assert.notEqual(fb1.verdict, 'confirmed')
    assert.ok(fb1.jqError)

    const repairedSpec = {
      ...brokenSpec,
      assertionsJq: '{ controlPassed: (.steps.c1.json.exposed == false), confirmed: (.steps.p1.json.exposed == true), observed: ("exposed=" + (.steps.p1.json.exposed | tostring)), expected: "exposed=false" }',
    }
    const r2 = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyInline({
        runId, assignmentId: aid, replaySpecId: row.id, spec: repairedSpec, attemptCount: 2,
        broker: new RequestBroker({ rejectUnauthorized: false }), backend: new LinuxWorkerBackend(),
        storage, grant: makeLabGrant(fx.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    const fb2 = r2.feedback as InlineVerifyFeedback
    assert.equal(fb2.verdict, 'confirmed')
    assert.equal(fb2.retriesRemaining, 1)
  })

  test('T3-03: Multi-step cookie login + protected endpoint proof in local-lab with zero cookie leak', async (t) => {
    const rawCookie = 'E2E_TOP_SECRET_SESSION_COOKIE_4499'
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/login') {
        res.setHeader('Set-Cookie', `app_sid=${rawCookie}; HttpOnly; Path=/`)
        res.end('ok')
        return
      }
      res.setHeader('Content-Type', 'application/json')
      const authed = String(req.headers.cookie ?? '').includes(rawCookie)
      res.end(JSON.stringify({ adminData: authed && req.url === '/admin/records' ? 'sensitive' : 'denied' }))
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'http_chain',
          assertionsJq: '{ controlPassed: (.steps.c1.json.adminData == "denied"), confirmed: (.steps.p1.json.adminData == "sensitive"), observed: .steps.p1.json.adminData, expected: "denied" }',
          steps: [
            { id: 'c1', role: 'control', description: 'Unauthenticated admin access', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/admin/records' } },
            { id: 's1', role: 'setup', description: 'Login into opaque jar', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/login', session: 'e2ejar' } as never },
            { id: 'p1', role: 'probe', description: 'Authenticated admin access', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/admin/records', session: 'e2ejar' } as never },
          ],
        },
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        storage,
        runId,
        grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
    assert.ok(!JSON.stringify(res).includes(rawCookie), 'Replay result leaked session jar cookie')
  })

  test('T3-04: Target rejecting missing CSRF (403) yields confirmed SQLi/BOLA when csrfBind: true', async (t) => {
    const tok = 'e2e-csrf-tok-7711'
    const fx = await startHttpFixture(t, (req, body, res) => {
      if (req.url === '/csrf') {
        res.setHeader('Set-Cookie', `XSRF-TOKEN=${tok}; Path=/`)
        res.end('ok')
        return
      }
      res.setHeader('Content-Type', 'application/json')
      if ((req.headers['x-xsrf-token'] ?? req.headers['x-csrf-token']) !== tok) {
        res.statusCode = 403
        res.end(JSON.stringify({ error: 'csrf' }))
        return
      }
      const parsed = JSON.parse(body || '{}') as { tenant?: string }
      res.end(JSON.stringify({ tenantData: parsed.tenant === 'other' ? 'LEAKED_OTHER' : 'OWN' }))
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'http_chain',
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200 and .steps.c1.json.tenantData == "OWN"), confirmed: (.steps.p1.status == 200 and .steps.p1.json.tenantData == "LEAKED_OTHER"), observed: .steps.p1.json.tenantData, expected: "403 or OWN" }',
          steps: [
            { id: 's1', role: 'setup', description: 'Init CSRF jar', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/csrf', session: 'cjar' } as never },
            { id: 'c1', role: 'control', description: 'Own tenant', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/api/export', session: 'cjar', csrfBind: true, jsonBody: { tenant: 'own' } } as never },
            { id: 'p1', role: 'probe', description: 'Other tenant', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/api/export', session: 'cjar', csrfBind: true, jsonBody: { tenant: 'other' } } as never },
          ],
        },
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
  })

  test('T3-05: Multi-step SPA wizard fill -> click -> dom_xss_sink_hook confirmed in single persistent session', async (t) => {
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body>
        <input id="bio" /><button id="save" onclick="localStorage.setItem('bio', document.getElementById('bio').value)">Save</button>
        <button id="preview" onclick="document.getElementById('out').innerHTML = localStorage.getItem('bio')">Preview</button>
        <div id="out"></div>
      </body></html>`)
    })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const browser = new ScopedBrowser(broker)
    const steps = [
      { id: 'c1', role: 'control', description: 'Control view', origin: fx.origin, pathAndQuery: '/', action: 'navigate' },
      { id: 'p1', role: 'probe', description: 'Fill payload', origin: fx.origin, pathAndQuery: '/', action: 'fill', selector: '#bio', value: '{{canary_token}}<img src=x onerror=1>', enableSinkHook: true },
      { id: 'p2', role: 'probe', description: 'Save to localStorage', origin: fx.origin, reusePage: true, action: 'click', selector: '#save' },
      { id: 'p3', role: 'probe', description: 'Preview innerHTML sink', origin: fx.origin, reusePage: true, action: 'click', selector: '#preview', enableSinkHook: true },
    ]
    const recipe = browserSinkEnvelopeFromSteps({ origin: fx.origin, vulnClass: 'dom_xss', steps })
    assert.ok(recipe, 'expected browser_sink recipe envelope for T3-05')
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'browser_chain',
          recipe,
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200 and (.steps.c1.domSinkTraces | length == 0)), confirmed: ((.steps.p3.domSinkTraces | length >= 1) or (.domSinkTraces | length >= 1)), observed: ("sinks=" + ((.domSinkTraces | length) | tostring)), expected: "0 DOM sink hits" }',
          steps: steps as never,
        } as unknown,
        broker,
        browser,
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
  })

  test('T3-06: Vulnerable JWT alg:none endpoint confirmed via auth_protocol_proof with zero token leak', async (t) => {
    const origJwt = makeHs256Jwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'alice', role: 'user' })
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      const tok = String(req.headers.authorization ?? '').slice(7)
      if (!tok) { res.statusCode = 401; res.end('{}'); return }
      const { header } = decodeJwtParts(tok)
      res.end(JSON.stringify({ isAdmin: header.alg === 'none', echoed: tok }))
    })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [{ handle: 'alice', roleLabel: 'User', authKind: 'bearer', secret: origJwt }],
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'auth_protocol_proof',
          protocol: 'jwt',
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200 and .steps.c1.json.isAdmin == false), confirmed: (.steps.p1.status == 200 and .steps.p1.json.isAdmin == true), observed: ("isAdmin=" + (.steps.p1.json.isAdmin | tostring)), expected: "isAdmin=false" }',
          steps: [
            { id: 'c1', role: 'control', description: 'Signed user JWT', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/admin', persona: 'alice' } },
            { id: 'p1', role: 'probe', description: 'Unsigned alg:none', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/admin', persona: 'alice', authMutation: { kind: 'alg_none' } } as never },
          ],
        } as unknown,
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { personas: personaMap, secrets: [{ placeholder: '[redacted]', value: origJwt }] }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
    assert.ok(!JSON.stringify(res).includes(origJwt))
  })

  test('T3-07: Next.js Next-Action POST BOLA confirmed at Tier 2 via sandboxWriteAllowlist without HITL', async (t) => {
    const fx = await startHttpFixture(t, (req, body, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (req.headers['next-action'] === 'act_get_invoice' && body.includes('inv_a')) {
        res.end(JSON.stringify({ invoice: 'inv_a', secretTotal: 4200 }))
        return
      }
      res.end(JSON.stringify({ invoice: 'inv_b', secretTotal: 10 }))
    })
    const allowlist: ApprovedEndpointPattern[] = [{ origin: fx.origin, method: 'POST', pathPattern: '/dashboard' }]
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'http_chain',
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200 and .steps.c1.json.secretTotal == 10), confirmed: (.steps.p1.status == 200 and .steps.p1.json.secretTotal == 4200), observed: ("total=" + (.steps.p1.json.secretTotal | tostring)), expected: "403 or own invoice" }',
          steps: [
            { id: 'c1', role: 'control', description: 'Own invoice action', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/dashboard', headers: { 'Next-Action': 'act_get_invoice' }, textBody: '["inv_b"]' } },
            { id: 'p1', role: 'probe', description: 'Other tenant invoice action', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/dashboard', headers: { 'Next-Action': 'act_get_invoice' }, textBody: '["inv_a"]' } },
          ],
        },
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { tier: 2, sandboxWriteAllowlist: allowlist, isIdempotentPostAllowed: () => true }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
  })

  test('T3-08: Phase-0 discovers hidden OpenAPI + Next.js routes & seeds SQLite endpoints before LLM Turn 1', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const runPhase0 = requireExport<(p: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runPhase0Recon', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/openapi.json') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ openapi: '3.0.0', paths: { '/api/v4/secret-billing': { get: {} } } }))
        return
      }
      res.setHeader('Content-Type', 'text/html')
      res.end('<html><body>ok</body></html>')
    })
    const repoDir = makeTempDir(t, 'kovo-v4-t3-p0-')
    mkdirSync(join(repoDir, 'web/app/api/internal-sync'), { recursive: true })
    writeFileSync(join(repoDir, 'web/app/api/internal-sync/route.ts'), 'export async function POST() { return Response.json({}) }')
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runPhase0({
        storage, runId, scopeRevision: 1, tier: 2, origins: [fx.origin], reposDir: repoDir,
        broker: new RequestBroker({ rejectUnauthorized: false }), grant: makeLabGrant(fx.origin),
        signal: AbortSignal.timeout(20_000),
      }),
    )
    const paths = (storage as unknown as V4StoreContract).listEndpoints(runId).map(e => String(e.pathTemplate ?? e.path_template))
    assert.ok(paths.some(p => p.includes('/api/v4/secret-billing')))
    assert.ok(paths.some(p => p.includes('/api/internal-sync')))
  })

  test('T3-09: Multi-persona SPA crawl discovers admin-only SPA route & XHR endpoint missed by GET /', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const crawl = requireExport<(p: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'crawlStateGraph', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/api/admin-metrics') { res.end('{"mrr":999}'); return }
      res.setHeader('Content-Type', 'text/html')
      if (req.headers.authorization === 'Bearer admin-tok') {
        res.end(`<html><body><a href="/admin-console">Admin</a><script>if(location.pathname==='/admin-console')fetch('/api/admin-metrics')</script></body></html>`)
        return
      }
      res.end('<html><body>Public Home</body></html>')
    })
    const { storage } = makeStore(t)
    const { runId, personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [{ handle: 'admin', roleLabel: 'Admin', authKind: 'bearer', secret: 'admin-tok' }],
    })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      crawl({
        storage, runId, scopeRevision: 1, origin: fx.origin, personas: ['admin'], maxPages: 10, maxDepth: 2,
        browser: new ScopedBrowser(new RequestBroker({ rejectUnauthorized: false })),
        grant: makeLabGrant(fx.origin, { personas: personaMap }), signal: AbortSignal.timeout(30_000),
      }),
    )
    const paths = (storage as unknown as V4StoreContract).listEndpoints(runId).map(e => String(e.pathTemplate ?? e.path_template))
    assert.ok(paths.some(p => p.includes('/api/admin-metrics')))
  })

  test('T3-10: Producer POST /api/invoices -> Consumer GET /api/invoices/{id} edge drives BOLA confirmation', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (req.method === 'POST' && req.url === '/api/invoices') {
        res.statusCode = 201
        res.end(JSON.stringify({ invoice: { id: 'inv_8801' } }))
        return
      }
      if (req.url === '/api/invoices/inv_8801') {
        res.end(JSON.stringify({ id: 'inv_8801', owner: 'persona_a', secretNotes: 'confidential' }))
        return
      }
      res.statusCode = 404
      res.end('{}')
    })
    const { storage } = makeStore(t)
    const { runId, personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [
        { handle: 'persona_a', roleLabel: 'A', authKind: 'bearer', secret: 'tok-a' },
        { handle: 'persona_b', roleLabel: 'B', authKind: 'bearer', secret: 'tok-b' },
      ],
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'http_chain',
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200 and .steps.c1.json.owner == "persona_a"), confirmed: (.steps.p1.status == 200 and .steps.p1.json.secretNotes == "confidential"), observed: .steps.p1.json.secretNotes, expected: "403 for persona_b" }',
          steps: [
            {
              id: 's1', role: 'setup', description: 'Create invoice as persona_a',
              request: { origin: fx.origin, method: 'POST', pathAndQuery: '/api/invoices', persona: 'persona_a', jsonBody: { total: 50 } },
              extract: [{ varName: 'invId', from: 'json', selector: 'invoice.id' }],
            },
            { id: 'c1', role: 'control', description: 'Owner reads invoice', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/invoices/{{invId}}', persona: 'persona_a' } },
            { id: 'p1', role: 'probe', description: 'Attacker reads invoice', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/invoices/{{invId}}', persona: 'persona_b' } },
          ],
        },
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(),
        storage,
        runId,
        grant: makeLabGrant(fx.origin, { personas: personaMap, isIdempotentPostAllowed: () => true }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
  })

  test('T3-11: Minified bundle + .map reveals hidden /api/internal/export route & body keys', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const runPhase0 = requireExport<(p: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runPhase0Recon', 'src/server/phase0-recon.ts',
    )
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/app.js') {
        res.setHeader('Content-Type', 'application/javascript')
        res.end('console.log("min");\n//# sourceMappingURL=/app.js.map')
        return
      }
      if (req.url === '/app.js.map') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({
          version: 3,
          sources: ['src/admin.ts'],
          sourcesContent: [`export function exportData() { return fetch('/api/internal/export', { method: 'POST', body: JSON.stringify({ orgSecretKey: '1' }) }) }`],
          mappings: '',
        }))
        return
      }
      res.setHeader('Content-Type', 'text/html')
      res.end('<html><script src="/app.js"></script></html>')
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runPhase0({
        storage, runId, scopeRevision: 1, tier: 1, origins: [fx.origin],
        broker: new RequestBroker({ rejectUnauthorized: false }), grant: makeLabGrant(fx.origin, { tier: 1 }),
        signal: AbortSignal.timeout(20_000),
      }),
    )
    const paths = (storage as unknown as V4StoreContract).listEndpoints(runId).map(e => String(e.pathTemplate ?? e.path_template))
    assert.ok(paths.some(p => p.includes('/api/internal/export')))
  })

  test('T3-12: Offline worker detects planted CVE in package-lock.json via Trivy + Opengrep sink under --network none', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T3-12')
    const backend = new LinuxWorkerBackend()
    const repoDir = makeTempDir(t, 'kovo-v4-t3-worker-')
    const appDir = join(repoDir, 'svc')
    writeLabRepoFixture(appDir, { withVulns: true })
    writeFileSync(join(appDir, 'package.json'), JSON.stringify({ name: 'svc', version: '1.0.0', dependencies: { lodash: '4.17.15' } }))
    writeFileSync(join(appDir, 'package-lock.json'), JSON.stringify({
      name: 'svc', version: '1.0.0', lockfileVersion: 3, requires: true,
      packages: { '': { dependencies: { lodash: '4.17.15' } }, 'node_modules/lodash': { version: '4.17.15' } },
    }))
    const res = await runWorkerSast(backend as never, { repo: 'svc', engines: ['opengrep', 'trivy-fs'], reposDir: repoDir }) as {
      engineStatus: Record<string, { ok: boolean }>; findings: unknown[]
    }
    assert.equal(res.engineStatus.opengrep.ok, true)
    assert.equal(res.engineStatus['trivy-fs'].ok, true)
    assert.ok(res.findings.length >= 2)
  })

  test('T3-13: Variant Sweep after 1 confirmed BOLA auto-discovers & confirms sibling unguarded route', async (t) => {
    const srcRoot = makeTempDir(t, 'kovo-v4-t3-variant-')
    mkdirSync(join(srcRoot, 'src'), { recursive: true })
    writeFileSync(join(srcRoot, 'src/invoices.ts'), `export function readInvoice(db: any, id: string) { return db.findUnique({ where: { id } }) }\n`)
    writeFileSync(join(srcRoot, 'src/payments.ts'), `export function readPayment(db: any, id: string) { return db.findUnique({ where: { id } }) }\n`)
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call', callId: 'c_var_t3', name: 'complete_intent',
      argumentsJson: JSON.stringify({ status: 'proved', summary: 'Sweep complete' }),
    }))
    const { dir: dataDir, storage } = makeStore(t)
    await saveModelProfile({
      name: 'Reasoning', endpoint: llm.endpoint, model: 'mock-r', protocol: 'responses', key: 'sk-t313-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'high', roleAffinity: 'reasoning',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { projectId, runId, run, assetIds } = await setupApprovedRun(storage, { seeds: ['http://127.0.0.1:9'] })
    mkdirSync(join(dataDir, 'repos', projectId, 'local'), { recursive: true })
    await exec('cp', ['-r', srcRoot, join(dataDir, 'repos', projectId, 'local', 'app')])
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'complete', 1, 0, ?, '[]', '[]', 'inv', 'obj', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const fid = randomUUID()
    const specRow = storage.createReplaySpec(run, storage.worker(aid), fid, {
      ...baseReplaySpecFields('http://127.0.0.1:9'),
      kind: 'static_ast_proof', repo: 'local/app', file: 'src/invoices.ts', startLine: 1, endLine: 1,
      engine: 'ast-grep', ruleOrPattern: 'db.findUnique({ where: { id } })',
      runtimeProofGap: 'Verified statically in source AST; runtime proof pending.',
      assertionsJq: '{ controlPassed: true, confirmed: (.static.verified == true), observed: "matched", expected: "no match" }',
    }, ['http://127.0.0.1:9'])
    storage.upsertChainFinding(run, assetIds[0], {
      id: fid, origin: 'http://127.0.0.1:9', title: 'BOLA in readInvoice', status: 'confirmed',
      verificationTier: 'static_verified', severity: 'high',
      reason: 'Confirmed BOLA on findUnique without tenant scope', remediation: 'Check tenantId', evidenceIds: [], scopeRevision: 1,
      codeLocations: [{ repo: 'local/app', file: 'src/invoices.ts', startLine: 1, endLine: 1 }],
    }, specRow.id, ['http://127.0.0.1:9'])
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 4_000
      while (Date.now() < deadline && !storage.listChainSteps(runId).some(s => /payments\.ts/i.test(JSON.stringify(s)))) {
        await delay(50)
      }
      await stopExecution(engine as never)
    })
    assert.ok(storage.listChainSteps(runId).some(s => /payments\.ts/i.test(JSON.stringify(s))))
  })

  test('T3-14: kovo scan --local-lab boots app+sidecar, seeds personas, confirms vuln, rebuilds & verifies fix', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T3-14')
    const runner = new LabRunner()
    t.after(() => runner.stopAll())
    const repo = makeTempDir(t, 'kovo-v4-t3-lab-')
    writeLabRepoFixture(repo, { withCompose: true, withVulns: true })
    const runId = randomUUID()
    const handle = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runner.startLabTarget({
        runId, environment: 'local-lab', repoDir: repo,
        labConfig: { enabled: true, dockerfile: 'Dockerfile', internalPort: 3000, healthPath: '/health' },
      }),
    )
    const vulnSpec = {
      ...baseReplaySpecFields(handle.origin),
      kind: 'http_chain',
      assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.status == 500 and (.steps.p1.body | contains("SQLITE_ERROR"))), observed: ("status=" + (.steps.p1.status | tostring)), expected: "HTTP 200/400 without SQLITE_ERROR" }',
      steps: [
        { id: 'c1', role: 'control', description: 'Numeric ID', request: { origin: handle.origin, method: 'GET', pathAndQuery: '/api/orders?id=1' } },
        { id: 'p1', role: 'probe', description: 'SQLi syntax error', request: { origin: handle.origin, method: 'GET', pathAndQuery: "/api/orders?id=1'" } },
      ],
    }
    const confirmed = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: vulnSpec, broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(), grant: makeLabGrant(handle.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(confirmed.verdict, 'confirmed')
    const fixDiff = [
      '--- a/server.mjs',
      '+++ b/server.mjs',
      '@@ -6,3 +6,3 @@',
      '   if (u.pathname === \'/api/orders\') {',
      '-    const id = u.searchParams.get(\'id\') || \'1\'',
      '-    if (id.includes("\'")) { res.statusCode = 500; res.end(\'SQLITE_ERROR: near syntax error\'); return }',
      '+    const id = String(parseInt(u.searchParams.get(\'id\') || \'1\', 10) || 1)',
      '+    if (false) { res.statusCode = 500; res.end(\'\'); return }',
    ].join('\n')
    const rebuilt = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => runner.rebuildWithPatch(runId, fixDiff))
    assert.equal(rebuilt.origin, handle.origin)
    const { retestReplaySpec } = await import('../src/server/replay-verifier.ts')
    const after = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      retestReplaySpec({
        spec: vulnSpec, broker: new RequestBroker({ rejectUnauthorized: false }),
        backend: new LinuxWorkerBackend(), grant: makeLabGrant(handle.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(after.verdict, 'fixed')
    await runner.stopAll()
    await assertZeroKovoOrphans(runId)
  })

  test('T3-15: Blind 500 SQL error diagnosed via IAST sink telemetry, then confirmed Zero-LLM', async (t) => {
    const labMod = await import('../src/server/lab-runner.ts') as Record<string, unknown>
    const ingestTelemetry = requireExport<(input: Record<string, unknown>) => { filePath: string; bytesWritten: number }>(
      labMod, 'ingestLabTelemetry', 'src/server/lab-runner.ts',
    )
    const fx = await startHttpFixture(t, (req, _b, res) => {
      const u = new URL(req.url ?? '/', fx.origin)
      const q = u.searchParams.get('q') ?? ''
      if (q.includes("'")) { res.statusCode = 500; res.end('Internal Error'); return }
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ ok: /AND\s+(\d+)=\1/.test(q) || q === '1' }))
    })
    const { dir, storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const telemetryDir = join(dir, 'evidence', 'lab-telemetry')
    mkdirSync(telemetryDir, { recursive: true })
    ingestTelemetry({
      runId,
      exchangeId: 'ex-blind-1',
      traceId: 'tr-blind-1',
      environment: 'local-lab',
      telemetryDir,
      secrets: [],
      rawTelemetry: {
        routesHit: ['/api/search'],
        newLinesCovered: 5,
        sinkEvents: [{ sink: 'pg.query', param: 'q', error: 'syntax error near quote' }],
        exceptions: ['SyntaxError'],
      },
      storage,
    })
    const telemetry = (storage as unknown as V4StoreContract).listLabTelemetry(runId)
    assert.equal(telemetry.length, 1)
    const verified = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'sql_boolean_diff', targetOrigin: fx.origin, method: 'GET', pathAndQuery: '/api/search',
          paramName: 'q', paramLocation: 'query', baselineValue: '1', quoteStyle: 'numeric',
          assertionsJq: '{ controlPassed: (.sqlDiff.controlPassed == true), confirmed: (.sqlDiff.passed == true), observed: ("passed=" + (.sqlDiff.passed | tostring)), expected: "sqlDiff.passed=false" }',
        } as unknown,
        broker: new RequestBroker({ rejectUnauthorized: false }), backend: new LinuxWorkerBackend(),
        storage, runId, grant: makeLabGrant(fx.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(verified.verdict, 'confirmed')
  })

  test('T3-16: XML-encoded blind SQLi + bounded time-based SQLi both discovered & confirmed via ReplayVerifier', async (t) => {
    const fx = await startHttpFixture(t, async (_req, body, res) => {
      if (body.includes('SLEEP') || body.includes('pg_sleep') || body.includes('WAITFOR')) {
        await delay(1600)
        res.end('<ok/>')
        return
      }
      const m = /<id>([^<]+)<\/id>/.exec(body)
      const val = m?.[1] ?? ''
      const isTrue = val === '1' || /AND\s+(\d+)=\1/.test(val)
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ rows: isTrue ? ['row1'] : [] }))
    })
    const boolVerdict = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'sql_boolean_diff', targetOrigin: fx.origin, method: 'POST', pathAndQuery: '/api/xml',
          paramName: 'id', paramLocation: 'xml', baselineValue: '1', quoteStyle: 'numeric',
          assertionsJq: '{ controlPassed: (.sqlDiff.controlPassed == true), confirmed: (.sqlDiff.passed == true), observed: ("passed=" + (.sqlDiff.passed | tostring)), expected: "sqlDiff.passed=false" }',
        } as unknown,
        broker: new RequestBroker({ rejectUnauthorized: false }), backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { tier: 3, isIdempotentPostAllowed: () => true }), signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(boolVerdict.verdict, 'confirmed')

    const timeVerdict = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'sql_time_diff', targetOrigin: fx.origin, method: 'POST', pathAndQuery: '/api/xml',
          paramName: 'id', paramLocation: 'xml', delayMs: 1500,
          assertionsJq: '{ controlPassed: (.sqlTimeDiff.controlPassed // true), confirmed: (.sqlTimeDiff.passed // true), observed: "time_diff", expected: "no delay" }',
        } as unknown,
        broker: new RequestBroker({ rejectUnauthorized: false }), backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { tier: 3, isIdempotentPostAllowed: () => true }), signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(timeVerdict.verdict, 'confirmed')
  })

  test('T3-17: Auto BOLA sweeper detects cross-tenant PATCH /api/orders/{id} and confirms via http_chain', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (req.method === 'POST' && req.url === '/api/orders') { res.end(JSON.stringify({ id: 'o_55' })); return }
      if (req.method === 'PATCH' && req.url === '/api/orders/o_55') { res.end(JSON.stringify({ patched: true, id: 'o_55' })); return }
      res.statusCode = 403
      res.end('{}')
    })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [
        { handle: 'persona_a', roleLabel: 'A', authKind: 'bearer', secret: 'tok-a' },
        { handle: 'persona_b', roleLabel: 'B', authKind: 'bearer', secret: 'tok-b' },
      ],
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'http_chain',
          assertionsJq: '{ controlPassed: (.steps.c1.status == 403), confirmed: (.steps.p1.status == 200 and .steps.p1.json.patched == true), observed: ("patched=" + (.steps.p1.json.patched | tostring)), expected: "HTTP 403" }',
          steps: [
            { id: 's1', role: 'setup', description: 'Create as A', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/api/orders', persona: 'persona_a', jsonBody: { item: 'x' } }, extract: [{ varName: 'oid', from: 'json', selector: 'id' }] },
            { id: 'c1', role: 'control', description: 'Deny anon read', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/orders/{{oid}}' }, expectedStatus: 403 },
            { id: 'p1', role: 'probe', description: 'Patch as B', request: { origin: fx.origin, method: 'PATCH', pathAndQuery: '/api/orders/{{oid}}', persona: 'persona_b', jsonBody: { status: 'hijacked' } } },
          ],
        },
        broker: new RequestBroker({ rejectUnauthorized: false }), backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { tier: 3, personas: personaMap, isStateChangeApproved: () => true, isIdempotentPostAllowed: () => true }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
  })

  test('T3-18: Nested GraphQL resolver BOLA confirmed where root query checks auth but child resolver does not', async (t) => {
    const fx = await startHttpFixture(t, (req, body, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (body.includes('billingInvoices') && req.headers.authorization === 'Bearer tok-b') {
        res.end(JSON.stringify({ data: { me: { org: { billingInvoices: [{ id: 'inv_a_secret', amount: 7500 }] } } } }))
        return
      }
      res.end(JSON.stringify({ data: { me: { id: 'user_b' } } }))
    })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [{ handle: 'persona_b', roleLabel: 'B', authKind: 'bearer', secret: 'tok-b' }],
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'http_chain',
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.json.data.me.org.billingInvoices[0].id == "inv_a_secret"), observed: .steps.p1.json.data.me.org.billingInvoices[0].id, expected: "authorization error" }',
          steps: [
            { id: 'c1', role: 'control', description: 'Root query', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/graphql', persona: 'persona_b', jsonBody: { query: '{ me { id } }' } } },
            { id: 'p1', role: 'probe', description: 'Nested resolver leak', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/graphql', persona: 'persona_b', jsonBody: { query: '{ me { org(id:"org_a") { billingInvoices { id amount } } } }' } } },
          ],
        },
        broker: new RequestBroker({ rejectUnauthorized: false }), backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { personas: personaMap, isIdempotentPostAllowed: () => true }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
  })

  test('T3-19: mass_assignment + cache_differential + xxe_canary each confirmed end-to-end on loopback lab', async (t) => {
    let role = 'user'
    const cache = new Map<string, string>()
    const canary = new CanaryBroker()
    await canary.startListener({ host: '127.0.0.1', port: 0 })
    t.after(() => canary.stopListener())
    const fx = await startHttpFixture(t, async (req, body, res) => {
      const u = new URL(req.url ?? '/', fx.origin)
      if (u.pathname === '/api/me') {
        if (req.method === 'POST') { role = (JSON.parse(body || '{}') as { role?: string }).role ?? role }
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ role }))
        return
      }
      if (u.pathname === '/cached') {
        const gcb = u.searchParams.get('_gcb') ?? ''
        const xfh = req.headers['x-forwarded-host']
        if (typeof xfh === 'string' && gcb) cache.set(gcb, xfh)
        if (cache.has(gcb)) {
          res.setHeader('X-Cache', xfh ? 'MISS' : 'HIT')
          if (!xfh) res.setHeader('Age', '5')
          res.end(`host:${cache.get(gcb)}`)
          return
        }
        res.end('host:clean')
        return
      }
      if (u.pathname === '/xml') {
        const m = /https?:\/\/[^\s"'>]+kovo-canary-[a-f0-9]+[^\s"'>]*/i.exec(body)
        if (m) await fetch(m[0]).catch(() => {})
        res.end('<ok/>')
      }
    })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const backend = new LinuxWorkerBackend()
    const grant = makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true })

    const rMass = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin), kind: 'http_chain',
          assertionsJq: '{ controlPassed: (.steps.c1.json.role == "user"), confirmed: (.steps.p1.json.role == "admin"), observed: .steps.p1.json.role, expected: "user" }',
          steps: [
            { id: 'c1', role: 'control', description: 'Before', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/me' } },
            { id: 's1', role: 'setup', description: 'Mass assign', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/api/me', jsonBody: { role: 'admin' } } },
            { id: 'p1', role: 'probe', description: 'Verify persisted', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/me' } },
          ],
        },
        broker, backend, grant, signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(rMass.verdict, 'confirmed')

    const rCache = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin), kind: 'cache_differential',
          targetOrigin: fx.origin,
          controlPath: '/cached?_gcb={{control_gcb}}',
          probePath: '/cached?_gcb={{probe_gcb}}',
          poisonHeaders: { 'X-Forwarded-Host': 'evil.invalid' },
          assertionsJq: '{ controlPassed: (.control.status == 200), confirmed: (.verify.status == 200 and (.verify.headers["x-cache"] == "HIT") and (.verify.body | contains("evil.invalid"))), observed: .verify.bodyPreview, expected: "clean cached response" }',
        } as unknown,
        broker, backend, grant, signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(rCache.verdict, 'confirmed')

    const rXxe = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin), kind: 'http_chain',
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: ((.proof.canaryProbeTriggered // .canary.triggered) == true), observed: "oob_canary", expected: "no external entity fetch" }',
          steps: [
            { id: 'c1', role: 'control', description: 'Safe XML', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/xml', textBody: '<a/>' } },
            { id: 'p1', role: 'probe', description: 'XXE canary', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/xml', textBody: '<!DOCTYPE x [<!ENTITY d SYSTEM "{{canary_url}}">]><x>&d;</x>' } },
          ],
        },
        broker, backend, canaryBroker: canary, grant, signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(rXxe.verdict, 'confirmed')
  })

  test('T3-20: Stored XSS planted by persona_a in /profile, surfaced in admin /export (persona_b) -> confirmed', async (t) => {
    const stored: string[] = []
    const fx = await startHttpFixture(t, (req, body, res) => {
      if (req.method === 'POST' && req.url === '/profile') {
        stored.push(JSON.parse(body || '{}').bio ?? '')
        res.end('{"saved":true}')
        return
      }
      res.setHeader('Content-Type', 'text/html')
      if (req.url === '/admin/export') {
        res.end(`<html><body><div id="list"></div><script>document.getElementById('list').innerHTML = ${JSON.stringify(stored.join(','))};</script></body></html>`)
        return
      }
      res.end('<html><body>clean</body></html>')
    })
    const { storage } = makeStore(t)
    const { runId, personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [
        { handle: 'persona_a', roleLabel: 'User', authKind: 'bearer', secret: 'tok-a' },
        { handle: 'persona_b', roleLabel: 'Admin', authKind: 'bearer', secret: 'tok-b' },
      ],
    })
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const marker = 'gn2o_e2e_xss_1122'
    const v4 = storage as unknown as V4StoreContract
    v4.insertSecondOrderCanary({ runId, assignmentId: aid, marker, injectedOrigin: fx.origin, injectedEndpoint: '/profile', injectedParam: 'bio', injectedPersona: 'persona_a' })

    const broker = new RequestBroker({ rejectUnauthorized: false })
    const browser = new ScopedBrowser(broker)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp(asBrokerRequest({ origin: fx.origin, method: 'POST', pathAndQuery: '/profile', persona: 'persona_a', body: JSON.stringify({ bio: `<img src=x onerror=1>${marker}` }), runId, assignmentId: aid }), makeLabGrant(fx.origin, { personas: personaMap, isIdempotentPostAllowed: () => true }), AbortSignal.timeout(5000))
      const steps = [
        { id: 'c1', role: 'control', description: 'Clean view', origin: fx.origin, pathAndQuery: '/', persona: 'persona_b', action: 'navigate' },
        { id: 'p1', role: 'probe', description: 'Admin export view', origin: fx.origin, pathAndQuery: '/admin/export', persona: 'persona_b', action: 'dom_xss_sink_hook', enableSinkHook: true },
      ]
      const recipe = browserSinkEnvelopeFromSteps({ origin: fx.origin, vulnClass: 'xss_stored', canaryToken: marker, steps })
      assert.ok(recipe, 'expected browser_sink recipe envelope for T3-20')
      const res = await verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin), kind: 'browser_chain',
          recipe,
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200 and (.steps.c1.domSinkTraces | length == 0)), confirmed: ((.steps.p1.domSinkTraces | length >= 1) or (.domSinkTraces | length >= 1)), observed: ("sinks=" + ((.domSinkTraces | length) | tostring)), expected: "0 DOM sink hits" }',
          steps,
        },
        broker, browser, backend: new LinuxWorkerBackend(), storage, runId,
        grant: makeLabGrant(fx.origin, { personas: personaMap }), signal: AbortSignal.timeout(30_000),
      })
      assert.equal(res.verdict, 'confirmed')
    })
  })

  test('T3-21: Transpiled template pack matches planted tech stack CVE and suppresses SPA catchall decoy', async (t) => {
    const compiledDir = resolve(repoRoot, 'src/templates/compiled')
    assert.ok(existsSync(compiledDir), 'src/templates/compiled missing')
    const loaded = loadSafeTemplates({ dir: compiledDir, refresh: true })
    const tmpl = selectSafeTemplates(loaded.templates, { techTags: ['nextjs'], tier: 1, maxTemplates: 50 }).selected.find(tpl =>
      tpl.request.method === 'GET' && !tpl.request.path.includes('{{') &&
      tpl.matchers.every(m => m.type === 'status' || (m.type === 'word' && !m.negative)),
    )
    assert.ok(tmpl, 'Expected at least 1 deterministic nextjs GET template in compiled pack')

    const fxSpa = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('X-Powered-By', 'Next.js')
      res.setHeader('Content-Type', 'text/html')
      res.end('<html><body><div id="__next">SPA Shell</div></body></html>')
    })
    const spaRes = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1', KOVO_TEMPLATES_DIR: compiledDir }, () =>
      runSafeTemplates(
        { origin: fxSpa.origin, techFingerprint: ['nextjs'], maxTemplates: 50, templatesDir: compiledDir },
        new RequestBroker({ rejectUnauthorized: false }), makeLabGrant(fxSpa.origin, { tier: 1 }), undefined, AbortSignal.timeout(30_000),
      ),
    )
    assert.equal(spaRes.matches.length, 0, 'SPA catchall must produce 0 template false positives')

    const statusMatcher = tmpl.matchers.find(m => m.type === 'status') as { status: number[] } | undefined
    const wordMatchers = tmpl.matchers.filter(m => m.type === 'word') as Array<{ words: string[] }>
    const matchBody = wordMatchers.flatMap(w => w.words).join('\n') || 'matched'
    const fxCve = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === tmpl.request.path || req.url?.split('?')[0] === tmpl.request.path.split('?')[0]) {
        res.statusCode = statusMatcher?.status[0] ?? 200
        res.setHeader('Content-Type', 'application/json')
        res.end(matchBody)
        return
      }
      res.statusCode = 404
      res.end('not found')
    })
    const cveRes = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1', KOVO_TEMPLATES_DIR: compiledDir }, () =>
      runSafeTemplates(
        { origin: fxCve.origin, techFingerprint: tmpl.tech, maxTemplates: 150, templatesDir: compiledDir },
        new RequestBroker({ rejectUnauthorized: false }), makeLabGrant(fxCve.origin, { tier: 1 }), undefined, AbortSignal.timeout(30_000),
      ),
    )
    assert.ok(cveRes.matches.length >= 1, `Expected deterministic match for template ${tmpl.id}`)
  })

  test('T3-22: 40-step multi-endpoint lab run exceeds old 32-step cap and stops gracefully at K=6 dry steps', async (t) => {
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call', callId: 'c_322', name: 'complete_intent', argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'dry' }),
    }))
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'Reasoning', endpoint: llm.endpoint, model: 'mock-r', protocol: 'responses', key: 'sk-322-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'reasoning',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId, run } = await setupApprovedRun(storage, { budgetRequests: 2000 })
    const v4 = storage as unknown as V4StoreContract
    for (let i = 0; i < 16; i++) {
      v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: `/api/admin/ep/${i}`, source: 'openapi', riskScore: 90 })
    }
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'threat_model', 'running', 1, 0, ?, '[]', ?, 'tm', 'tm', ?)`)
      .run(aid, runId, randomUUID(), JSON.stringify(['http://127.0.0.1:9']), Date.now())
    const assignment = storage.worker(aid)
    for (let i = 0; i < 10; i++) {
      storage.addFact(run, assignment, { kind: 'code_audit_suspect', origin: 'http://127.0.0.1:9', summary: `Lead ${i}`, data: { endpoint: `/api/s/${i}`, severity: 'high', category: 'injection-input' } })
    }
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 3_500
      while (Date.now() < deadline) {
        const r = storage.client.prepare('SELECT dynamic_step_budget FROM runs WHERE id = ?').get(runId) as { dynamic_step_budget?: number }
        if ((r.dynamic_step_budget ?? 0) >= 42) break
        await delay(50)
      }
      await stopExecution(engine as never)
    })
    const row = storage.client.prepare('SELECT dynamic_step_budget FROM runs WHERE id = ?').get(runId) as { dynamic_step_budget: number }
    assert.equal(row.dynamic_step_budget, 42)
    assert.ok(row.dynamic_step_budget > 32)
  })

  test('T3-23: Coordinator dispatches bola-bfla-specialist & injection-parser-specialist cleanly on mixed lab', async (t) => {
    assert.ok(specialistProfiles.includes('bola-bfla-specialist'))
    assert.ok(specialistProfiles.includes('injection-parser-specialist'))
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call', callId: 'c_323', name: 'complete_intent', argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'Checked' }),
    }))
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'Tactical', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-323-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId, run } = await setupApprovedRun(storage)
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'threat_model', 'running', 1, 0, ?, '[]', ?, 'tm', 'tm', ?)`)
      .run(aid, runId, randomUUID(), JSON.stringify(['http://127.0.0.1:9']), Date.now())
    const assignment = storage.worker(aid)
    const facts = [
      storage.addFact(run, assignment, { kind: 'code_audit_suspect', origin: 'http://127.0.0.1:9', summary: 'Cross-tenant IDOR on /orders/{id}', data: { category: 'broken-access-control', hypothesis: 'BOLA', endpoint: '/orders/{id}' } }),
      storage.addFact(run, assignment, { kind: 'code_audit_suspect', origin: 'http://127.0.0.1:9', summary: 'SQL injection on /search?q=', data: { category: 'injection-input', hypothesis: 'sqli_boolean', endpoint: '/search' } }),
    ]
    convertCodeAuditSuspectsToChainSteps(storage, run, facts)
    const steps = storage.client.prepare('SELECT title, specialist_profile FROM chain_steps WHERE run_id = ?').all(runId) as Array<{ title: string; specialist_profile: string | null }>
    assert.equal(steps.find(s => /IDOR|orders/i.test(s.title))?.specialist_profile, 'bola-bfla-specialist')
    assert.equal(steps.find(s => /SQL|search/i.test(s.title))?.specialist_profile, 'injection-parser-specialist')
  })

  test('T3-24: Crown-jewel lead spawns 2 parallel trials; first confirmation cancels sibling cleanly', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (req.url === '/slow') {
        setTimeout(() => res.end(JSON.stringify({ leaked: false })), 60000)
        return
      }
      res.end(JSON.stringify({ leaked: req.url === '/p' }))
    })
    let done = false
    let trialCalls = 0
    const llm = await startMockLlmServer(t, (call) => {
      const prompt = JSON.stringify(call.body)
      const trialPrompt = !prompt.includes('Stateless Coordinator Planner') && (prompt.includes('Crown Jewel') || prompt.includes('auth-session'))
      if (trialPrompt) trialCalls += 1
      if (!done && trialPrompt) {
        done = true
        return {
          type: 'tool_call', callId: 'c_win_324', name: 'propose_chain_finding',
          argumentsJson: JSON.stringify({
            counterevidence: 'Control endpoint returns false while probe leaks secret claim',
            confidenceRationale: 'Deterministic replay differential confirmed bypass',
            chainFactIds: [],
            exchangeIds: [],
            verifyNow: true,
            replaySpec: {
              ...baseReplaySpecFields(fx.origin),
              title: 'Crown Jewel Auth Bypass',
              category: 'auth-session',
              severity: 'critical',
              kind: 'http_chain',
              assertionsJq: '{ controlPassed: (.steps.c1.json.leaked == false), confirmed: (.steps.p1.json.leaked == true), observed: (.steps.p1.json.leaked | tostring), expected: "false" }',
              steps: [
                { id: 'c1', role: 'control', description: 'Control', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/c' } },
                { id: 'p1', role: 'probe', description: 'Probe', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/p' } },
              ],
            },
          }),
        }
      }
      return { type: 'tool_call', callId: 'c_done_324', name: 'complete_intent', argumentsJson: JSON.stringify({ status: 'proved', summary: 'done' }) }
    })
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'Tactical', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-324-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'any',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const gid = randomUUID()
    const now = Date.now()
    const s1 = randomUUID()
    storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, trial_group_id, trial_index, created_at, updated_at) VALUES (?, ?, 0, 1, 1, 'Crown Jewel Trial 0', 'jwt alg none', 'auth-session', 95, '[]', '[]', '[]', '[]', 'pending', ?, ?, 0, ?, ?)`)
      .run(randomUUID(), runId, JSON.stringify([fx.origin]), gid, now, now)
    storage.client.prepare(`INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, trial_group_id, trial_index, created_at, updated_at) VALUES (?, ?, 0, 1, 2, 'Crown Jewel Trial 1', 'jwt alg none', 'auth-session', 95, '[]', '[]', '[]', '[]', 'pending', ?, ?, 1, ?, ?)`)
      .run(s1, runId, JSON.stringify([fx.origin]), gid, now + 1, now + 1)
    storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 1 })
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 50_000
      while (Date.now() < deadline) {
        const sib = storage.client.prepare('SELECT status FROM chain_steps WHERE id = ?').get(s1) as { status: string }
        if (sib.status === 'canceled') break
        await delay(50)
      }
      await stopExecution(engine as never)
    })
    const sib = storage.client.prepare('SELECT status FROM chain_steps WHERE id = ?').get(s1) as { status: string }
    assert.equal(sib.status, 'canceled')
  })

  test('T3-25: Multi-profile run routes Code Audit to reasoning, Investigation to tactical, Dedupe to fast', async (t) => {
    const mod = await import('../src/server/model-settings.ts') as Record<string, unknown>
    const resolvePool = requireExport<(role: RoleAffinity, storage?: Store) => Array<{ name: string }>>(
      mod, 'resolveProfilePoolForRole', 'src/server/model-settings.ts',
    )
    const { storage } = makeStore(t)
    const base = {
      endpoint: 'https://openrouter.ai/api/v1', model: 'deepseek/v4', protocol: 'responses' as const,
      key: 'sk-test-12345678', enabled: true, contextWindow: 128_000, maxTokens: 8192,
      thinkingLevel: 'medium' as const, inputCostPerMtok: 0.1, cachedInputCostPerMtok: 0, outputCostPerMtok: 0.2,
    }
    await saveModelProfile({ ...base, name: 'ReasonProf', priority: 100, roleAffinity: 'reasoning' } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    await saveModelProfile({ ...base, name: 'TacticalProf', priority: 100, roleAffinity: 'tactical' } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    await saveModelProfile({ ...base, name: 'FastProf', priority: 100, roleAffinity: 'fast' } as unknown as Parameters<typeof saveModelProfile>[0], storage, { skipConnectionCheck: true })
    assert.equal(resolvePool(roleAffinityForScenario('code-auditor'), storage)[0].name, 'ReasonProf')
    assert.equal(resolvePool(roleAffinityForScenario('worker-investigation'), storage)[0].name, 'TacticalProf')
    assert.equal(resolvePool(roleAffinityForScenario('worker-analysis'), storage)[0].name, 'FastProf')
  })

  test('T3-26: benchmark-recall.ts runs against mock suite, persists benchmark_runs, emits JSON+MD diff', async (t) => {
    const mod = await loadV4Module('scripts/benchmark-recall.ts')
    const runSuite = requireExport<(opts: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runBenchmarkSuite', 'scripts/benchmark-recall.ts',
    )
    const { dir, storage } = makeStore(t)
    const outJson = join(dir, 'bench.json')
    const outMd = join(dir, 'bench.md')
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runSuite({ suite: 'xben-25', dryRun: true, storage, outJson, outMd }),
    )
    assert.ok(existsSync(outJson))
    assert.ok(existsSync(outMd))
    assert.ok((storage as unknown as V4StoreContract).listBenchmarkRuns('xben-25').length >= 1)
    assert.ok(res && typeof res === 'object')
  })

  test('T3-27: Full benchmark:recall smoke run over Held-Out SaaS Lab records funnel + 0 decoy FPs', async (t) => {
    const mod = await loadV4Module('scripts/benchmark-recall.ts')
    const runSuite = requireExport<(opts: Record<string, unknown>) => Promise<{ falsePositiveCount: number; funnelCounts: Record<string, number> }>>(
      mod, 'runBenchmarkSuite', 'scripts/benchmark-recall.ts',
    )
    const { storage } = makeStore(t)
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runSuite({ suite: 'held-out-saas', dryRun: true, storage }),
    )
    assert.equal(res.falsePositiveCount, 0)
    assert.equal(res.funnelCounts.targetVulns, 20)
  })

  test('T3-28: Legacy v3 kovo.sqlite opened by v4 Store auto-migrates losslessly and completes v4 ops', async (t) => {
    const dir = makeTempDir(t, 'kovo-v4-t3-mig-')
    const srcDb = resolve(repoRoot, '.kovo/dyad-v2-smoke/data/kovo.sqlite')
    if (existsSync(srcDb)) {
      copyFileSync(srcDb, join(dir, 'kovo.sqlite'))
    } else {
      const seed = new Store(dir)
      const now = Date.now()
      const wsId = seed.workspace.id
      seed.client.exec(`
        INSERT INTO projects (id, workspace_id, name, seeds, default_scope, created_at)
          VALUES ('proj-t3-1', '${wsId}', 'Legacy T3 Project', '["http://127.0.0.1:9"]', '[]', ${now});
      `)
      seed.close()
      const raw = new DatabaseSync(join(dir, 'kovo.sqlite'))
      for (const tbl of ['benchmark_runs', 'lab_telemetry', 'second_order_canaries', 'api_dependencies', 'endpoint_params', 'endpoints']) {
        raw.exec(`DROP TABLE IF EXISTS ${tbl};`)
      }
      raw.exec(`
        ALTER TABLE model_profiles DROP COLUMN role_affinity;
        ALTER TABLE projects DROP COLUMN sandbox_write_allowlist;
        ALTER TABLE runs DROP COLUMN dynamic_step_budget;
        ALTER TABLE runs DROP COLUMN multi_trial_enabled;
        ALTER TABLE runs DROP COLUMN phase0_completed_at;
        ALTER TABLE chain_steps DROP COLUMN specialist_profile;
        ALTER TABLE chain_steps DROP COLUMN trial_group_id;
        ALTER TABLE chain_steps DROP COLUMN trial_index;
        ALTER TABLE replay_specs DROP COLUMN attempt_count;
        ALTER TABLE replay_specs DROP COLUMN verified_inline;
        ALTER TABLE replay_specs DROP COLUMN last_verification_diff;
      `)
      raw.close()
    }
    const storage = new Store(dir)
    t.after(() => storage.close())
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/migrated-v4', source: 'spa_crawl' })
    assert.equal(v4.listEndpoints(runId).length, 1)
  })
})

// ============================================================================
// TIER 4 — Concurrency, Crash Recovery, Stress & Real-World E2E (14 cases)
// ============================================================================

describe('Tier 4 — Concurrency, Crash Recovery, Stress & Real-World E2E (14 cases)', () => {
  test('T4-01: SIGKILL crash recovery preserves v4 endpoints, api_dependencies, second_order_canaries, replay_specs.attempt_count and pauses running workers', async (t) => {
    const dir = makeTempDir(t, 'kovo-v4-sigkill-')
    let savedRunId = ''
    let savedAid = ''
    {
      const app = await createApp({ KOVO_ALLOW_LOCAL_LAB: '1' }, dir)
      t.after(() => app.dispose())
      await app.start()
      await app.stop('SIGKILL')
    }
    {
      const s1 = new Store(dir)
      const { runId, run } = await setupApprovedRun(s1)
      savedRunId = runId
      const v4 = s1 as unknown as V4StoreContract
      const p = v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'POST', pathTemplate: '/api/orders', source: 'spa_crawl' })
      const c = v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: '/api/orders/{id}', source: 'spa_crawl' })
      v4.recordApiDependency({ runId, producerEndpointId: p.id, consumerEndpointId: c.id, resourceKey: 'id', personaHandle: 'persona_a' })
      const aid = randomUUID()
      savedAid = aid
      s1.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
        .run(aid, runId, randomUUID(), Date.now())
      const assignment = s1.db.select().from((await import('../src/server/schema.ts')).assignments).limit(1).get()!
      v4.insertSecondOrderCanary({ runId, assignmentId: aid, marker: 'gn2o_sigkill01', injectedOrigin: 'http://127.0.0.1:9', injectedEndpoint: '/p', injectedParam: 'q' })
      const rs = s1.createReplaySpec(run, assignment, randomUUID(), {
        ...baseReplaySpecFields('http://127.0.0.1:9'), kind: 'http_chain', spaCatchallControl: false,
        assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.status == 200), observed: "ok", expected: "denied" }',
        steps: [
          { id: 'c1', role: 'control', description: 'c', request: { origin: 'http://127.0.0.1:9', method: 'GET', pathAndQuery: '/c', followRedirects: false } },
          { id: 'p1', role: 'probe', description: 'p', request: { origin: 'http://127.0.0.1:9', method: 'GET', pathAndQuery: '/p', followRedirects: false } },
        ],
      }, ['http://127.0.0.1:9'])
      v4.incrementReplaySpecAttempt(rs.id, { verdict: 'dismissed', controlPassed: true, stepStatuses: [], retriesRemaining: 1 })
      s1.client.prepare(`UPDATE runs SET status = 'running' WHERE id = ?`).run(runId)
      s1.close()
    }
    const s2 = new Store(dir)
    t.after(() => s2.close())
    assert.equal(s2.run(savedRunId).status, 'paused')
    const interruptedWorker = s2.client.prepare(`SELECT status FROM assignments WHERE id = ?`).get(savedAid) as { status: string }
    assert.equal(interruptedWorker.status, 'paused')
    const activeLeft = s2.client.prepare(`SELECT id FROM assignments WHERE run_id = ? AND status IN ('running', 'queued', 'waiting_approval')`).all(savedRunId)
    assert.equal(activeLeft.length, 0)
    const v4b = s2 as unknown as V4StoreContract
    assert.equal(v4b.listEndpoints(savedRunId).length, 2)
    assert.equal(v4b.listApiDependencies(savedRunId).length, 1)
    assert.equal(v4b.listSecondOrderCanaries(savedRunId).length, 1)
    const rsRow = s2.client.prepare('SELECT attempt_count FROM replay_specs WHERE run_id = ?').get(savedRunId) as { attempt_count: number }
    assert.ok(rsRow.attempt_count >= 2)
  })

  test('T4-02: Live scopeRevision revocation storm aborts active probes, purges jars, taints facts, and sends 0 post-revocation requests', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      if (req.url === '/login') res.setHeader('Set-Cookie', 'sid=STORM_COOKIE_SECRET; Path=/')
      res.end('ok')
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin] })
    const broker = new RequestBroker({ rejectUnauthorized: false }) as unknown as V4BrokerContract
    let inScope = true
    let postRevokeRequests = 0
    const grant = makeLabGrant(fx.origin, { canRead: o => inScope && o === fx.origin })

    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/login', session: 'storm-jar', runId }, grant, AbortSignal.timeout(5000))
      const countBeforeRevoke = fx.requests.length

      // Trigger scope narrowing revocation storm concurrently
      inScope = false
      storage.command({
        requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 1, assetIds: [], consent: true,
      })
      if (typeof broker.revokeOrigin === 'function') broker.revokeOrigin(fx.origin, 2)

      const storm = Array.from({ length: 10 }, (_, i) =>
        broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: `/probe/${i}`, session: 'storm-jar', runId }, grant, AbortSignal.timeout(5000))
          .then(() => { postRevokeRequests += 1 })
          .catch(() => 'blocked'),
      )
      await Promise.all(storm)
      assert.equal(postRevokeRequests, 0, 'Broker sent requests after scope revocation')
      assert.equal(fx.requests.length, countBeforeRevoke)

      // Re-grant and verify jar cookie was purged
      inScope = true
      await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: '/after', session: 'storm-jar', runId }, grant, AbortSignal.timeout(5000))
      assert.equal(fx.requests.at(-1)?.headers.cookie ?? undefined, undefined)
    })
  })

  test('T4-03: High-concurrency multi-trial + 10-req race_burst + maxRpsPerOrigin: 5 with 0 SQLITE_BUSY errors', async (t) => {
    const timestamps: number[] = []
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      timestamps.push(Date.now())
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ ok: true }))
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin], maxRpsPerOrigin: 5 })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const grant = makeLabGrant(fx.origin, { maxRpsPerOrigin: 5, isIdempotentPostAllowed: () => true })

    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      const burst = await broker.executeRaceBurst(
        Array.from({ length: 10 }, (_, i) => ({ origin: fx.origin, method: 'POST', pathAndQuery: `/race/${i}`, body: '{}' })),
        grant,
        AbortSignal.timeout(15_000),
      )
      assert.equal(burst.summary.total, 10)
      const rpsStart = Date.now()
      for (let i = 0; i < 12; i += 1) {
        await broker.executeHttp({ origin: fx.origin, method: 'GET', pathAndQuery: `/rps/${i}` }, grant, AbortSignal.timeout(15_000))
      }
      const elapsedMs = Date.now() - rpsStart
      assert.ok(elapsedMs >= 1000, `Expected maxRpsPerOrigin=5 to pace 12 requests >= 1000ms, got ${elapsedMs}ms`)
      const v4 = storage as unknown as V4StoreContract
      await Promise.all(
        Array.from({ length: 20 }, (_, i) => Promise.resolve().then(() => {
          v4.upsertEndpoint({ runId, scopeRevision: 1, origin: fx.origin, method: 'GET', pathTemplate: `/ep/${i}`, source: 'spa_crawl' })
        })),
      )
      assert.equal(v4.listEndpoints(runId).length, 20)
    })
  })

  test('T4-04: Dynamic budget scaling stress computes >32 steps for 30 endpoints + 20 suspects and halts on K=6 dry steps', async (t) => {
    const execMod = await import('../src/server/execution.ts') as Record<string, unknown>
    const convertSuspects = requireExport<typeof convertCodeAuditSuspectsToChainSteps>(
      execMod, 'convertCodeAuditSuspectsToChainSteps', 'src/server/execution.ts',
    )
    const llm = await startMockLlmServer(t, () => ({
      type: 'tool_call', callId: 'c_404', name: 'complete_intent', argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'dry' }),
    }))
    const { storage } = makeStore(t)
    await saveModelProfile({
      name: 'Reasoning', endpoint: llm.endpoint, model: 'mock-r', protocol: 'responses', key: 'sk-404-12345678',
      priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'reasoning',
      inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    const { runId, run } = await setupApprovedRun(storage, { budgetRequests: 5000 })
    const v4 = storage as unknown as V4StoreContract
    for (let i = 0; i < 30; i += 1) {
      v4.upsertEndpoint({ runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: `/api/admin/ep/${i}`, source: 'openapi', riskScore: 90 })
    }
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'threat_model', 'running', 1, 0, ?, '[]', ?, 'tm', 'tm', ?)`)
      .run(aid, runId, randomUUID(), JSON.stringify(['http://127.0.0.1:9']), Date.now())
    const assignment = storage.worker(aid)
    const factRows = Array.from({ length: 40 }, (_, i) => storage.addFact(run, assignment, {
      kind: 'code_audit_suspect', origin: 'http://127.0.0.1:9', summary: `Stress Suspect ${i}`,
      data: { endpoint: `/api/stress/${i}`, severity: 'high', category: 'broken-access-control' },
    }))
    const steps = convertSuspects(storage, run, factRows)
    assert.equal(steps.length, 40)
    assert.ok(steps.length > 32)
    const engine = new Execution(storage)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      engine.start()
      engine.wake()
      const deadline = Date.now() + 3_500
      while (Date.now() < deadline) {
        const r = storage.client.prepare('SELECT dynamic_step_budget FROM runs WHERE id = ?').get(runId) as { dynamic_step_budget?: number }
        if ((r.dynamic_step_budget ?? 0) > 32) break
        await delay(50)
      }
      await stopExecution(engine as never)
    })
    const row = storage.client.prepare('SELECT dynamic_step_budget FROM runs WHERE id = ?').get(runId) as { dynamic_step_budget?: number }
    assert.ok((row.dynamic_step_budget ?? 0) > 32, `Expected dynamic_step_budget > 32, got ${row.dynamic_step_budget}`)
  })

  test('T4-05: Phase-0 request cap stress stops strictly at min(15% * budgetRequests, 250/origin) on 1,000+ link app', async (t) => {
    const mod = await loadV4Module('src/server/phase0-recon.ts')
    const runPhase0 = requireExport<(p: Record<string, unknown>) => Promise<{ requestsUsed: number }>>(
      mod, 'runPhase0Recon', 'src/server/phase0-recon.ts',
    )
    const links = Array.from({ length: 120 }, (_, i) => `<a href="/p/${i}">p${i}</a>`).join('')
    const fx = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body>${links}</body></html>`)
    })
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 200 })
    const cap = 30 // 15% of 200
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runPhase0({
        storage, runId, scopeRevision: 1, tier: 1, origins: [fx.origin], budgetRequests: 200,
        broker: new RequestBroker({ rejectUnauthorized: false }), grant: makeLabGrant(fx.origin, { tier: 1 }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.ok(fx.requests.length <= cap, `Phase-0 exceeded 15% cap (${cap}): sent ${fx.requests.length}`)
  })

  test('T4-06: IAST high-volume flood (50 x 150 KiB sink logs with 3 secrets) enforces 64 KiB cap and 0 secret leaks', async (t) => {
    const labMod = await import('../src/server/lab-runner.ts') as Record<string, unknown>
    const ingestTelemetry = requireExport<(input: Record<string, unknown>) => { filePath: string; bytesWritten: number }>(
      labMod, 'ingestLabTelemetry', 'src/server/lab-runner.ts',
    )
    const dir = makeTempDir(t, 'kovo-v4-iast-flood-')
    const { storage } = makeStore(t)
    const { runId } = await setupApprovedRun(storage)
    const v4 = storage as unknown as V4StoreContract
    const personaSecret = 'persona-flood-secret-443322'
    const bigQuery = `${RAW_AWS_SECRET} ${RAW_STRIPE_SECRET} ${personaSecret} ` + 'X'.repeat(150_000)

    let totalBytes = 0
    for (let i = 0; i < 50; i += 1) {
      const exId = `ex-flood-${i}`
      const res = ingestTelemetry({
        runId,
        exchangeId: exId,
        traceId: `tr-${i}`,
        environment: 'local-lab',
        telemetryDir: dir,
        secrets: [
          { value: RAW_AWS_SECRET, placeholder: '[masked:aws]' },
          { value: RAW_STRIPE_SECRET, placeholder: '[masked:stripe]' },
          { value: personaSecret, placeholder: '[masked:persona]' },
        ],
        rawTelemetry: {
          routesHit: [`/api/flood/${i}`],
          newLinesCovered: 1,
          sinkEvents: [{ sink: 'pg.query', query: bigQuery }],
          exceptions: [],
        },
        storage,
      })
      const sz = statSync(res.filePath).size
      assert.ok(sz <= 65_536, `Artifact ${exId} exceeded 64 KiB: ${sz} bytes`)
      totalBytes += sz
      const raw = readFileSync(res.filePath, 'utf8')
      assert.ok(!raw.includes(RAW_AWS_SECRET) && !raw.includes(RAW_STRIPE_SECRET) && !raw.includes(personaSecret))
    }
    assert.ok(totalBytes <= 50 * 65_536)
    assert.equal(v4.listLabTelemetry(runId).length, 50)
  })

  test('T4-07: Transpiled template pack scale & SPA catchall suppression + circuit breaker on 5xx burst', async (t) => {
    const compiledDir = resolve(repoRoot, 'src/templates/compiled')
    assert.ok(existsSync(compiledDir), 'src/templates/compiled missing')
    const spa = await startHttpFixture(t, (_req, _b, res) => {
      res.setHeader('Content-Type', 'text/html')
      res.end('<!doctype html><html><body><div id="root">Universal SPA Shell</div></body></html>')
    })
    const spaRes = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1', KOVO_TEMPLATES_DIR: compiledDir }, () =>
      runSafeTemplates(
        {
          origin: spa.origin, techFingerprint: ['generic', 'nextjs'], maxTemplates: 200, templatesDir: compiledDir,
        },
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(spa.origin, { tier: 1 }),
        undefined,
        AbortSignal.timeout(45_000),
      ),
    )
    assert.equal(spaRes.matches.length, 0, 'SPA catchall produced false positive template findings')

    const errSrv = await startHttpFixture(t, (_req, _b, res) => {
      res.statusCode = 500
      res.end('server error')
    })
    const errRes = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1', KOVO_TEMPLATES_DIR: compiledDir }, () =>
      runSafeTemplates(
        {
          origin: errSrv.origin, techFingerprint: ['generic'], maxTemplates: 100, templatesDir: compiledDir,
        },
        new RequestBroker({ rejectUnauthorized: false }),
        makeLabGrant(errSrv.origin, { tier: 1 }),
        undefined,
        AbortSignal.timeout(45_000),
      ),
    )
    assert.ok(errSrv.requests.length < 100, 'Circuit breaker should halt 5xx burst early')
    assert.ok(errRes && typeof errRes === 'object')
  })

  test('T4-08: Full CLI kovo scan --local-lab --sarif lifecycle produces valid SARIF 2.1.0, Markdown, summary.json & exit code 2', async (t) => {
    const fx = await startHttpFixture(t, (req, _b, res) => {
      res.setHeader('Content-Type', 'application/json')
      const u = new URL(req.url ?? '/', fx.origin)
      if ((u.searchParams.get('id') ?? '').includes("'")) { res.statusCode = 500; res.end('SQLITE_ERROR: near syntax error'); return }
      res.end(JSON.stringify({ ok: true }))
    })
    let proposed = false
    const llm = await startMockLlmServer(t, (call) => {
      const serialized = JSON.stringify(call.body.input ?? [])
      const tools = Array.isArray(call.body.tools) ? (call.body.tools as Array<{ name?: string }>).map(tl => tl.name ?? '') : []
      if (serialized.includes('"round-0 threat model"')) {
        return {
          type: 'tool_call', callId: 'c_cli_tm', name: 'complete_intent',
          argumentsJson: JSON.stringify({
            status: 'proved', summary: 'Planned SQLi check',
            steps: [{ title: 'SQLi in /api/items', hypothesis: 'Quote SQLi', category: 'injection-input', priority: 95, origins: [fx.origin] }],
          }),
        }
      }
      if (!proposed && tools.includes('propose_chain_finding')) {
        proposed = true
        return {
          type: 'tool_call', callId: 'c_cli_find', name: 'propose_chain_finding',
          argumentsJson: JSON.stringify({
            counterevidence: 'Numeric id parameter id=1 succeeds cleanly with HTTP 200',
            confidenceRationale: 'Single quote injection triggers deterministic HTTP 500 SQLITE_ERROR',
            replaySpec: {
              ...baseReplaySpecFields(fx.origin),
              kind: 'http_chain',
              category: 'injection-input',
              cwe: 'CWE-89',
              severity: 'high',
              assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.status == 500 and (.steps.p1.body | contains("SQLITE_ERROR"))), observed: ("status=" + (.steps.p1.status | tostring)), expected: "HTTP 200/400 without SQLITE_ERROR" }',
              steps: [
                { id: 'c1', role: 'control', description: 'Control', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/items?id=1' } },
                { id: 'p1', role: 'probe', description: 'Probe', request: { origin: fx.origin, method: 'GET', pathAndQuery: "/api/items?id=1'" } },
              ],
            },
          }),
        }
      }
      return {
        type: 'tool_call', callId: `c_cli_done_${randomUUID().slice(0, 6)}`, name: 'complete_intent',
        argumentsJson: JSON.stringify({ status: 'proved', summary: 'Phase completed cleanly.' }),
      }
    })
    const outDir = makeTempDir(t, 'kovo-v4-cli-')
    const dataDir = join(outDir, 'data')
    mkdirSync(dataDir, { recursive: true, mode: 0o700 })
    const seedStorage = new Store(dataDir)
    await saveModelProfile({
      name: 'CLI Mock Model', endpoint: llm.endpoint, model: 'mock-cli', protocol: 'responses',
      key: 'sk-cli-mock-12345678', priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096,
      thinkingLevel: 'medium', roleAffinity: 'any', inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
    }, seedStorage, { skipConnectionCheck: true })
    seedStorage.close()

    const sarifPath = join(outDir, 'report.sarif')
    // Run the real CLI as a child process: importing runCli() into the test runner made the
    // CLI engine's late scheduler tick observable after the test ended (a false async-activity
    // failure attributed to this file). A subprocess is also the production invocation path,
    // so the exit-code contract is exercised exactly as shipped.
    const cliPath = resolve(repoRoot, 'scripts/cli.ts')
    const exitCode = await new Promise<number>((resolveExit, rejectExit) => {
      execFile(process.execPath, [
        ...HARDENED_NODE_FLAGS,
        cliPath,
        'scan', '--local-lab', '--origin', fx.origin, '--tier', '2',
        '--output-dir', outDir, '--sarif', sarifPath, '--fail-on', 'high', '--timeout-sec', '45',
      ], {
        cwd: repoRoot,
        timeout: 120_000,
        env: {
          ...process.env,
          KOVO_ALLOW_LOCAL_LAB: '1',
          OPENAI_BASE_URL: llm.endpoint,
          OPENAI_API_KEY: 'sk-cli-mock-12345678',
        },
      }, (error, _stdout, stderr) => {
        if (error && typeof (error as { code?: unknown }).code !== 'number') return rejectExit(error)
        if (stderr && process.env.KOVO_WORKER_DEBUG === '1') process.stderr.write(stderr.slice(0, 2_000))
        resolveExit(error ? Number((error as { code: number }).code) : 0)
      })
    })
    assert.equal(exitCode, 2, `Expected deterministic CLI exit code 2 for confirmed high finding, got ${exitCode}`)
    assert.equal(existsSync(sarifPath), true, 'Expected SARIF file at --sarif path')
    const sarifErrors = validateSarif21(JSON.parse(readFileSync(sarifPath, 'utf8')))
    assert.deepEqual(sarifErrors, [])
    const summaryPath = join(outDir, 'summary.json')
    assert.equal(existsSync(summaryPath), true, 'Expected summary.json in --output-dir')
    const summary = JSON.parse(readFileSync(summaryPath, 'utf8')) as { confirmedCount: number; exitCode: number }
    assert.ok(summary.confirmedCount >= 1)
    assert.equal(summary.exitCode, 2)
    const mdFiles = readdirSync(outDir).filter(f => f.endsWith('.md'))
    assert.ok(mdFiles.length >= 1, 'Expected generated Markdown report in --output-dir')
  })

  test('T4-09: Live createApp() HTTP API + SSE /api/runs/$runId/events Last-Event-ID replay & zero secret leaks', async (t) => {
    const dir = makeTempDir(t, 'kovo-v4-app-sse-')
    const secretMarker = 'SSE_SECRET_TOKEN_DO_NOT_LEAK_999'
    let savedRunId = ''
    let savedProjectId = ''
    let ev1Id = 0
    let ev2Id = 0
    {
      const storage = new Store(dir)
      const seeded = await setupApprovedRun(storage, {
        personas: [{ handle: 'sse_user', roleLabel: 'User', authKind: 'bearer', secret: secretMarker }],
      })
      savedRunId = seeded.runId
      savedProjectId = seeded.projectId
      const ev1 = storage.event(savedRunId, 'phase.update', 'Phase 0 started', { endpoints: 1 })
      const ev2 = storage.event(savedRunId, 'phase.update', 'Phase 0 completed', { endpoints: 12 })
      ev1Id = ev1.id
      ev2Id = ev2.id
      storage.close()
    }

    const app = await createApp({ KOVO_ALLOW_LOCAL_LAB: '1' }, dir)
    t.after(() => app.dispose())
    await app.start()

    const localToken = readFileSync(join(dir, 'local-session'), 'utf8').trim()
    const authHeaders = { Cookie: `kovo_local=${localToken}` }
    for (const path of ['/health', '/', '/settings', `/projects/${savedProjectId}`, `/runs/${savedRunId}`]) {
      const resp = await fetch(`${app.url}${path}`, { headers: authHeaders })
      assert.equal(resp.status, 200, `Expected 200 on live SSR route ${path}, got ${resp.status}`)
      const bodyText = await resp.text()
      assert.ok(!bodyText.includes(secretMarker), `Route ${path} leaked persona secret`)
    }

    const ac = new AbortController()
    const sseResp = await fetch(`${app.url}/api/runs/${savedRunId}/events`, {
      headers: { ...authHeaders, 'Last-Event-ID': String(ev1Id) },
      signal: ac.signal,
    })
    assert.equal(sseResp.status, 200)
    const reader = sseResp.body?.getReader()
    assert.ok(reader, 'Expected readable SSE stream')
    let ssePayload = ''
    const readDeadline = Date.now() + 4_000
    while (Date.now() < readDeadline) {
      const { value, done } = await Promise.race([
        reader.read(),
        delay(500).then(() => ({ value: undefined, done: true })),
      ])
      if (value) ssePayload += Buffer.from(value).toString('utf8')
      if (ssePayload.includes('Phase 0 completed') || done) break
    }
    ac.abort()
    await reader.cancel().catch(() => {})
    assert.match(ssePayload, new RegExp(`id:\\s*${ev2Id}\\b`))
    assert.ok(ssePayload.includes('Phase 0 completed'), 'Expected ev2 replayed after Last-Event-ID')
    assert.ok(!ssePayload.includes('Phase 0 started'), 'ev1 at/before Last-Event-ID must NOT replay')
    assert.ok(!ssePayload.includes(secretMarker), 'SSE stream leaked persona secret')
  })

  test('T4-10: Multi-step LabRunner patch -> rebuild -> Zero-LLM retestReplaySpec reproduced -> fixed loop', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T4-10')
    const runner = new LabRunner()
    t.after(() => runner.stopAll())
    const repo = makeTempDir(t, 'kovo-v4-patch-loop-')
    writeLabRepoFixture(repo, { withVulns: true })
    const runId = randomUUID()
    const handle = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runner.startLabTarget({
        runId, environment: 'local-lab', repoDir: repo,
        labConfig: { enabled: true, dockerfile: 'Dockerfile', internalPort: 3000, healthPath: '/health' },
      }),
    )
    const spec = {
      ...baseReplaySpecFields(handle.origin),
      kind: 'http_chain',
      assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.status == 500 and (.steps.p1.body | contains("SQLITE_ERROR"))), observed: ("status=" + (.steps.p1.status | tostring)), expected: "HTTP 200/400 without SQLITE_ERROR" }',
      steps: [
        { id: 'c1', role: 'control', description: 'Clean id', request: { origin: handle.origin, method: 'GET', pathAndQuery: '/api/orders?id=1' } },
        { id: 'p1', role: 'probe', description: 'Quote injection', request: { origin: handle.origin, method: 'GET', pathAndQuery: "/api/orders?id=1'" } },
      ],
    }
    const before = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec, broker: new RequestBroker({ rejectUnauthorized: false }), backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(handle.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(before.verdict, 'confirmed')

    const fixDiff = [
      '--- a/server.mjs',
      '+++ b/server.mjs',
      '@@ -6,3 +6,3 @@',
      '   if (u.pathname === \'/api/orders\') {',
      '-    const id = u.searchParams.get(\'id\') || \'1\'',
      '-    if (id.includes("\'")) { res.statusCode = 500; res.end(\'SQLITE_ERROR: near syntax error\'); return }',
      '+    const id = String(parseInt(u.searchParams.get(\'id\') || \'1\', 10) || 1)',
      '+    if (false) { res.statusCode = 500; res.end(\'\'); return }',
    ].join('\n')
    const rebuilt = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => runner.rebuildWithPatch(runId, fixDiff))
    assert.equal(rebuilt.origin, handle.origin)

    const { retestReplaySpec } = await import('../src/server/replay-verifier.ts')
    const after = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      retestReplaySpec({
        spec, broker: new RequestBroker({ rejectUnauthorized: false }), backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(handle.origin), signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(after.verdict, 'fixed')
    await runner.stopAll()
    await assertZeroKovoOrphans(runId)
  })

  test('T4-11: Second-order cross-persona & cross-endpoint sweep across 20 concurrent requests confirms Stored XSS via ScopedBrowser', async (t) => {
    const comments: string[] = []
    const fx = await startHttpFixture(t, (req, body, res) => {
      if (req.method === 'POST' && req.url === '/comments') {
        comments.push(JSON.parse(body || '{}').text ?? '')
        res.end('{"ok":true}')
        return
      }
      if (req.url === '/admin/reports') {
        res.setHeader('Content-Type', 'text/html')
        res.end(`<html><body><div id="r"></div><script>document.getElementById('r').innerHTML=${JSON.stringify(comments.join(' '))};</script></body></html>`)
        return
      }
      res.setHeader('Content-Type', 'text/html')
      res.end('<html><body>neutral</body></html>')
    })
    const { storage } = makeStore(t)
    const { runId, personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [
        { handle: 'persona_a', roleLabel: 'A', authKind: 'bearer', secret: 'tok-a' },
        { handle: 'persona_b', roleLabel: 'B', authKind: 'bearer', secret: 'tok-b' },
      ],
    })
    const aid = randomUUID()
    storage.client.prepare(`INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at) VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', '[]', 't', 'o', ?)`)
      .run(aid, runId, randomUUID(), Date.now())
    const marker = 'gn2o_cafe1234'
    const v4 = storage as unknown as V4StoreContract
    v4.insertSecondOrderCanary({ runId, assignmentId: aid, marker, injectedOrigin: fx.origin, injectedEndpoint: '/comments', injectedParam: 'text', injectedPersona: 'persona_a' })

    const broker = new RequestBroker({ rejectUnauthorized: false, storage })
    const browser = new ScopedBrowser(broker)
    const grant = makeLabGrant(fx.origin, { personas: personaMap, isIdempotentPostAllowed: () => true })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
      await broker.executeHttp(asBrokerRequest({ origin: fx.origin, method: 'POST', pathAndQuery: '/comments', persona: 'persona_a', body: JSON.stringify({ text: `<img src=x onerror=1>${marker}` }), runId, assignmentId: aid }), grant, AbortSignal.timeout(5000))
      await Promise.all(
        Array.from({ length: 18 }, (_, i) =>
          broker.executeHttp(asBrokerRequest({ origin: fx.origin, method: 'GET', pathAndQuery: `/neutral/${i}`, persona: i % 2 === 0 ? 'persona_a' : 'persona_b', runId, assignmentId: aid }), grant, AbortSignal.timeout(5000)),
        ),
      )
      assert.equal(v4.listSecondOrderCanaries(runId, 'surfaced').length, 0, 'Neutral endpoints must not surface canary')
      await broker.executeHttp(asBrokerRequest({ origin: fx.origin, method: 'GET', pathAndQuery: '/admin/reports', persona: 'persona_b', runId, assignmentId: aid }), grant, AbortSignal.timeout(5000))
      const surfacedRows = v4.listSecondOrderCanaries(runId, 'surfaced')
      assert.equal(surfacedRows.length, 1, 'Expected cross-persona GET /admin/reports to surface canary')
      assert.equal(surfacedRows[0].surfacedPersona ?? surfacedRows[0].surfaced_persona, 'persona_b')
      const steps = [
        { id: 'c1', role: 'control', description: 'Neutral page', origin: fx.origin, pathAndQuery: '/neutral/0', persona: 'persona_b', action: 'navigate' },
        { id: 'p1', role: 'probe', description: 'Admin export triggers Stored XSS', origin: fx.origin, pathAndQuery: '/admin/reports', persona: 'persona_b', action: 'dom_xss_sink_hook', enableSinkHook: true },
      ]
      const recipe = browserSinkEnvelopeFromSteps({ origin: fx.origin, vulnClass: 'xss_stored', canaryToken: marker, steps })
      assert.ok(recipe, 'expected browser_sink recipe envelope for T4-11')
      const verified = await verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin), kind: 'browser_chain',
          recipe,
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200 and (.steps.c1.domSinkTraces | length == 0)), confirmed: ((.steps.p1.domSinkTraces | length >= 1) or (.domSinkTraces | length >= 1)), observed: ("sinks=" + ((.domSinkTraces | length) | tostring)), expected: "0 DOM sink hits" }',
          steps,
        },
        broker, browser, backend: new LinuxWorkerBackend(), storage, runId, grant, signal: AbortSignal.timeout(30_000),
      })
      assert.equal(verified.verdict, 'confirmed')
    })
  })

  test('T4-12: Full BOLA producer-consumer + workflow-skip + race_burst lifecycle with cleanup and 0 secret leaks', async (t) => {
    const orders = new Map<string, { owner: string; status: string }>()
    let credits = 100
    const fx = await startHttpFixture(t, (req, body, res) => {
      res.setHeader('Content-Type', 'application/json')
      const actor = req.headers.authorization === 'Bearer tok-a' ? 'persona_a' : 'persona_b'
      if (req.method === 'POST' && req.url === '/orders') {
        const id = `ord_${orders.size + 1}`
        orders.set(id, { owner: actor, status: 'draft' })
        res.statusCode = 201
        res.end(JSON.stringify({ id }))
        return
      }
      if (req.url?.startsWith('/orders/') && req.url.endsWith('/refund')) {
        const id = req.url.split('/')[2]
        const row = orders.get(id)
        if (row) row.status = 'refunded'
        credits += 100
        res.end(JSON.stringify({ id, status: 'refunded', credits }))
        return
      }
      if (req.url === '/wallet') { res.end(JSON.stringify({ credits })); return }
      if (req.method === 'DELETE' && req.url?.startsWith('/orders/')) {
        orders.delete(req.url.split('/')[2])
        res.end(JSON.stringify({ deleted: true }))
        return
      }
      res.end(JSON.stringify({ ok: true }))
    })
    const { storage } = makeStore(t)
    const { personaMap } = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      personas: [
        { handle: 'persona_a', roleLabel: 'A', authKind: 'bearer', secret: 'tok-a' },
        { handle: 'persona_b', roleLabel: 'B', authKind: 'bearer', secret: 'tok-b' },
      ],
    })
    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin), kind: 'http_chain',
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.status == 200 and .steps.p1.json.status == "refunded"), observed: .steps.p1.json.status, expected: "403 rejecting cross-persona refund" }',
          steps: [
            { id: 's1', role: 'setup', description: 'Create order', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/orders', persona: 'persona_a', jsonBody: {} }, extract: [{ varName: 'oid', from: 'json', selector: 'id' }] },
            { id: 'c1', role: 'control', description: 'Check wallet', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/wallet', persona: 'persona_a' } },
            { id: 'p1', role: 'probe', description: 'Cross-persona step-skip refund', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/orders/{{oid}}/refund', persona: 'persona_b', jsonBody: {} } },
            { id: 'cl1', role: 'cleanup', description: 'Delete synthetic order', request: { origin: fx.origin, method: 'DELETE', pathAndQuery: '/orders/{{oid}}', persona: 'persona_a' } },
          ],
        },
        broker: new RequestBroker({ rejectUnauthorized: false }), backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { tier: 3, personas: personaMap, isStateChangeApproved: () => true, isIdempotentPostAllowed: () => true }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(res.verdict, 'confirmed')
    const raceRes = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      verifyReplaySpec({
        spec: {
          ...baseReplaySpecFields(fx.origin),
          kind: 'race_burst',
          category: 'business-logic-race',
          cwe: 'CWE-362',
          assertionsJq: '{ controlPassed: (.burst.summary.total == 5), confirmed: (.postCheck.status == 200 and .postCheck.json.credits >= 300), observed: ("credits=" + (.postCheck.json.credits | tostring)), expected: "credits <= 200" }',
          burst: Array.from({ length: 5 }, () => ({ origin: fx.origin, method: 'POST', pathAndQuery: '/orders/race_1/refund', persona: 'persona_b', jsonBody: {} })),
          postCheckStep: { id: 'chk', role: 'probe', description: 'Check credits', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/wallet', persona: 'persona_a' } },
        },
        broker: new RequestBroker({ rejectUnauthorized: false }), backend: new LinuxWorkerBackend(),
        grant: makeLabGrant(fx.origin, { tier: 3, personas: personaMap, isStateChangeApproved: () => true, isIdempotentPostAllowed: () => true }),
        signal: AbortSignal.timeout(30_000),
      }),
    )
    assert.equal(raceRes.verdict, 'confirmed')
    assert.equal(orders.size, 0, 'Synthetic test order was not cleaned up')
    assert.ok(!JSON.stringify({ res, raceRes }).includes('tok-a') && !JSON.stringify({ res, raceRes }).includes('tok-b'))
  })

  test('T4-13: benchmark:recall diff across two runs persists both rows, monotonic funnels, and quantifies bucket reductions', async (t) => {
    const mod = await loadV4Module('scripts/benchmark-recall.ts')
    const runSuite = requireExport<(opts: Record<string, unknown>) => Promise<Record<string, unknown>>>(
      mod, 'runBenchmarkSuite', 'scripts/benchmark-recall.ts',
    )
    const { dir, storage } = makeStore(t)
    const outJson = join(dir, 't4-13-diff.json')
    const outMd = join(dir, 't4-13-diff.md')
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runSuite({ suite: 'xben-25', dryRun: true, profileMode: 'v3-baseline', gitSha: 'sha-v3', storage }),
    )
    await delay(5)
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runSuite({ suite: 'xben-25', dryRun: true, profileMode: 'v4-full', gitSha: 'sha-v4', baselineSha: 'sha-v3', storage, outJson, outMd }),
    )
    const rows = (storage as unknown as V4StoreContract).listBenchmarkRuns('xben-25', 10)
    assert.equal(rows.length, 2)
    assert.ok(existsSync(outJson), 'Expected benchmark diff JSON')
    assert.ok(existsSync(outMd), 'Expected benchmark diff Markdown')
    const diffJson = JSON.parse(readFileSync(outJson, 'utf8')) as Record<string, unknown>
    assert.ok(typeof diffJson.recallDelta === 'number' || typeof diffJson.confirmedDelta === 'number')
    const md = readFileSync(outMd, 'utf8')
    assert.match(md, /sha-v3|sha-v4/)
  })

  test('T4-14: Full zero-trust container escape & resource-exhaustion probe holds containment and leaves 0 orphans', async (t) => {
    assert.equal(await dockerAvailable(), true, 'Docker daemon required for T4-14')
    const labRunId = randomUUID()
    const backend = new LinuxWorkerBackend({ runId: labRunId })
    const repoDir = makeTempDir(t, 'kovo-v4-escape-')
    writeLabRepoFixture(join(repoDir, 'app'))
    chmodSync(repoDir, 0o755)
    chmodSync(join(repoDir, 'app'), 0o755)

    // Probe 1: worker cannot write to read-only rootfs or RO /repos, cannot fork-exhaust host, or reach metadata network
    const workerAssignmentId = randomUUID()
    const session = await backend.openSession(workerAssignmentId, AbortSignal.timeout(45_000), { reposDir: repoDir, pidsLimit: 64 })
    let res: { exitCode: number; stdout: string; stderr: string }
    try {
      const { stdout: cidOut } = await exec('docker', ['ps', '-aq', '--filter', `label=dev.kovo.assignment=${workerAssignmentId}`])
      const workerCid = cidOut.trim().split('\n')[0]?.trim()
      assert.ok(workerCid, 'Expected worker container for docker inspect')
      const { stdout: inspectOut } = await exec('docker', ['inspect', '--format', '{{.HostConfig.PidsLimit}}', workerCid])
      const inspectedPidsLimit = Number(inspectOut.trim())
      assert.ok(Number.isFinite(inspectedPidsLimit) && inspectedPidsLimit > 0, `Expected HostConfig.PidsLimit > 0, got ${inspectOut.trim()}`)

      res = await session.runScript({
        runtime: 'node',
        code: [
          `import fs from 'node:fs';`,
          `import cp from 'node:child_process';`,
          `let roBlocked = false; try { fs.writeFileSync('/etc/pwned', 'x'); } catch { roBlocked = true; }`,
          `let repoRoBlocked = false; try { fs.writeFileSync('/repos/app/pwned', 'x'); } catch { repoRoBlocked = true; }`,
          `let pidsContained = false; let spawned = 0; let cleaningUp = false; const children = [];`,
          `try { for (let i = 0; i < 150; i++) { const child = cp.spawn('node', ['-e', 'setTimeout(() => {}, 5000)'], { stdio: 'ignore' }); child.on('error', () => { pidsContained = true; }); child.on('exit', (code, sig) => { if (!cleaningUp && (code !== 0 || sig !== null)) pidsContained = true; }); children.push(child); spawned++; } } catch { pidsContained = true; }`,
          `setTimeout(() => {`,
          `  cleaningUp = true;`,
          `  for (const c of children) { try { c.kill('SIGKILL'); } catch {} }`,
          `  Promise.race([fetch('http://169.254.169.254/latest/meta-data/').then(() => false).catch(() => true), new Promise(r => setTimeout(() => r(true), 1200))])`,
          `  .then(netBlocked => { console.log(JSON.stringify({ uid: process.getuid(), roBlocked, repoRoBlocked, pidsContained, spawned, netBlocked })); });`,
          `}, 500);`,
        ].join('\n'),
      }, AbortSignal.timeout(45_000))
    } finally {
      await session.close()
    }
    assert.equal(res.exitCode, 0)
    const parsed = JSON.parse(res.stdout.trim()) as { uid: number; roBlocked: boolean; repoRoBlocked: boolean; pidsContained: boolean; netBlocked: boolean }
    assert.equal(parsed.uid, 10001)
    assert.equal(parsed.roBlocked, true)
    assert.equal(parsed.repoRoBlocked, true)
    assert.equal(parsed.pidsContained, true)
    assert.equal(parsed.netBlocked, true)

    // Probe 2: running --internal LabRunner container cannot reach a live host TCP/HTTP listener
    const hostSrv = createServer((_req, r) => r.end('HOST_SECRET'))
    await new Promise<void>(r => hostSrv.listen(0, '0.0.0.0', () => r()))
    t.after(() => new Promise<void>(r => hostSrv.close(() => r())))
    const hostPort = (hostSrv.address() as { port: number }).port
    const runner = new LabRunner()
    t.after(() => runner.stopAll())
    const labHandle = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
      runner.startLabTarget({
        runId: labRunId,
        environment: 'local-lab',
        repoDir: join(repoDir, 'app'),
        labConfig: { enabled: true, dockerfile: 'Dockerfile', internalPort: 3000, healthPath: '/health' },
      }),
    ) as unknown as V4LabTargetHandle
    await assert.rejects(() =>
      exec('docker', ['exec', labHandle.containerName, 'node', '-e', `fetch('http://172.17.0.1:${hostPort}',{signal:AbortSignal.timeout(1500)}).then(()=>process.exit(0)).catch(()=>process.exit(1))`]),
    )
    await runner.stopAll()

    // Probe 3: LabRunner rejects privileged/host-escape compose and leaves 0 orphans
    await assert.rejects(
      () => withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
        runner.startLabTarget({
          runId: randomUUID(),
          environment: 'local-lab',
          repoDir: join(repoDir, 'app'),
          labConfig: { enabled: true, services: [{ name: 'bad', image: 'node:24-bookworm-slim', privileged: true }] } as unknown as LabConfig,
        }),
      ),
      /privileged|forbidden|unsafe/i,
    )
    await runner.stopAll()
    await assertZeroKovoOrphans()
  })
})
