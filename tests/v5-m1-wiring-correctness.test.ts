/**
 * Kovo v5 M1-core: P0 wiring, canary correlation, dedupe, routing & feedback correctness.
 *
 * Covers plans/v5.md M1.1–M1.5 as owned by the m1-core stream:
 *   1.1 storage/session/csrfBind/authMutation/traceId/runId/assignmentId wiring in Execution
 *   1.2 second-order canary minting + multi-surface tracking + bounded callback capture
 *   1.3 dedupe extractors for all ReplaySpec kinds and `(method, primary param)` fingerprints
 *   1.4 specialist skill resolution, weighted routing, deterministic skill pre-injection
 *   1.5 enriched InlineVerifyFeedback + bounded Phase-3 refinement eligibility
 *
 * No benchmark/app/route/param hardcoding: every fixture below is generic and synthetic.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { randomUUID } from 'node:crypto'
import { newProject } from '../src/domain.ts'
import type { Finding } from '../src/domain.ts'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import {
  SPECIALIST_PROFILES,
  chainPlannerPrompt,
  routeStepToSpecialist,
  workerInvestigationPrompt,
} from '../src/server/agent-session.ts'
import {
  CanaryBroker,
  resetSecondOrderSurfaceTracking,
  scanSecondOrderMarkers,
} from '../src/server/canary-broker.ts'
import {
  checkStructuralDuplicate,
  computeFindingFingerprint,
  extractSpecDedupeFields,
} from '../src/server/dedupe.ts'
import { Execution } from '../src/server/execution.ts'
import { assessBflaImpact, buildInlineVerifyFeedback } from '../src/server/replay-verifier.ts'
import { templateIdsForCves } from '../src/server/cve-broker.ts'
import type { BrokerExchangeResult } from '../src/server/broker.ts'
import { loadSkill, listSkills, selectPreInjectionSkills } from '../src/server/skills.ts'
import { Store } from '../src/server/store.ts'
import { LinuxWorkerBackend, formatWorkerFailure } from '../src/server/worker-backend.ts'
import type { Assignment, Run } from '../src/server/store.ts'
import { setupApprovedRun, startHttpFixture, withEnv } from './v4-tier-helpers.ts'

const repoRoot = resolve(new URL('..', import.meta.url).pathname)
const executionSource = readFileSync(join(repoRoot, 'src/server/execution.ts'), 'utf8')
const transportSource = readFileSync(join(repoRoot, 'src/server/exec-brokered-transport.ts'), 'utf8')
const fakeOrigin = 'https://app.example.invalid'

function makeStore(t: { after: (fn: () => void) => void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v5-m1-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })
  return storage
}

function baseReplayFields(origin: string) {
  return {
    version: 1 as const,
    origin,
    title: 'Defensive differential proof',
    category: 'injection-input',
    cwe: 'CWE-89',
    severity: 'high' as const,
    severityRationale: 'Deterministic differential divergence observed.',
    impact: 'Unauthorized read of another tenant record.',
    remediation: 'Parameterize the query and enforce tenant scope.',
    recheckInstructions: 'Re-run the replay spec after the fix.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "x", expected: "y" }',
  }
}

// ============================================================================
// 1.4 Skill slugs, weighted routing & pre-injection
// ============================================================================

test('M1.4: every SPECIALIST_PROFILES skill slug resolves to a real src/skills/*.md file', () => {
  const known = new Set(listSkills().map(s => s.name))
  const missing: string[] = []
  for (const [profileId, cfg] of Object.entries(SPECIALIST_PROFILES)) {
    for (const slug of cfg.skills) {
      if (!known.has(slug)) missing.push(`${profileId}:${slug}`)
    }
  }
  assert.deepEqual(missing, [], `Unresolved skill slugs: ${missing.join(', ')}`)
  assert.ok(known.has('cache-smuggling-desync'), 'cache-smuggling-desync skill must exist')
})

test('M1.4: injection/auth/client/business profiles reference the documented playbooks', () => {
  assert.ok(SPECIALIST_PROFILES['injection-parser-specialist'].skills.includes('sqli-boolean-differential'))
  assert.ok(SPECIALIST_PROFILES['injection-parser-specialist'].skills.includes('ssti-non-destructive'))
  assert.ok(SPECIALIST_PROFILES['injection-parser-specialist'].skills.includes('xxe-canary-proof'))
  assert.ok(SPECIALIST_PROFILES['injection-parser-specialist'].skills.includes('injection-benign-proof'))
  assert.ok(SPECIALIST_PROFILES['injection-parser-specialist'].skills.includes('path-traversal-canonicalization'))
  assert.ok(SPECIALIST_PROFILES['auth-session-oauth-specialist'].skills.includes('jwt-session-security'))
  assert.ok(SPECIALIST_PROFILES['client-browser-dom-specialist'].skills.includes('client-side-xss-postmessage'))
  assert.ok(SPECIALIST_PROFILES['client-browser-dom-specialist'].skills.includes('prototype-pollution-dom-server'))
  assert.ok(SPECIALIST_PROFILES['business-logic-race-specialist'].skills.includes('business-logic-workflows'))
  assert.ok(SPECIALIST_PROFILES['business-logic-race-specialist'].skills.includes('mass-assignment-overposting'))
})

test('M1.4: weighted routing sends authorization-header JWT work to auth and SQLi-on-checkout to injection', () => {
  assert.equal(
    routeStepToSpecialist({ title: 'Test Authorization header JWT bypass', category: 'auth-identity' }),
    'auth-session-oauth-specialist',
  )
  assert.equal(
    routeStepToSpecialist({ title: 'SQLi on /checkout search', category: 'injection-input' }),
    'injection-parser-specialist',
  )
  // Bare `header`/`checkout` must no longer hijack unrelated steps.
  assert.equal(
    routeStepToSpecialist({ title: 'Cross-tenant invoice IDOR', hypothesis: 'Read another tenant invoice via checkout history', category: 'broken-access-control' }),
    'bola-bfla-specialist',
  )
  assert.equal(
    routeStepToSpecialist({ title: 'Shared cache poisoning on the marketing page', hypothesis: 'X-Forwarded-Host reflected into cached HTML' }),
    'protocol-cache-edge-specialist',
  )
  assert.equal(
    routeStepToSpecialist({ title: 'Coupon double-spend race', hypothesis: 'TOCTOU on single-use voucher redemption' }),
    'business-logic-race-specialist',
  )
  assert.equal(
    routeStepToSpecialist({ title: 'GraphQL nested resolver BOLA', endpoint: '/graphql' }),
    'graphql-api-specialist',
  )
})

test('M1.4: an explicit planner specialistProfile always wins over keyword scoring', () => {
  assert.equal(
    routeStepToSpecialist({ title: 'SQLi on /checkout search', specialistProfile: 'client-browser-dom-specialist' }),
    'client-browser-dom-specialist',
  )
  assert.equal(
    routeStepToSpecialist({ title: 'anything', specialistProfile: 'not-a-real-profile' }),
    'bola-bfla-specialist',
  )
})

test('M1.4: pre-injection deterministically selects 1-2 real playbooks by profile + tech + sink', () => {
  const cacheSkills = selectPreInjectionSkills({
    profileSkills: SPECIALIST_PROFILES['protocol-cache-edge-specialist'].skills,
    techTags: ['cdn'],
    sinkKind: 'redirect',
    title: 'Cache deception on authenticated route',
  })
  assert.ok(cacheSkills.length >= 1 && cacheSkills.length <= 2)
  assert.ok(cacheSkills.every(s => loadSkill(s.name) !== null))
  assert.ok(cacheSkills.some(s => s.name === 'cache-smuggling-desync'))
  assert.ok(cacheSkills[0].excerpt.length > 0 && cacheSkills[0].excerpt.length <= 1200)

  const injected = workerInvestigationPrompt({
    goal: 'defensive review',
    step: {
      id: 'step-1',
      title: 'Cache deception on authenticated route',
      hypothesis: 'A private page is stored by the shared cache.',
      category: 'misconfig-exposure',
      skills: ['cache-smuggling-desync'],
      specialistProfile: 'protocol-cache-edge-specialist',
    },
    origins: [fakeOrigin],
    capabilityTier: 2,
    maxTurns: 12,
    preInjectedSkills: cacheSkills,
  })
  const parsed = JSON.parse(injected) as { preInjectedSkills: Array<{ name: string; excerpt: string }> }
  assert.ok(parsed.preInjectedSkills.length >= 1)
  assert.equal(parsed.preInjectedSkills[0].name, cacheSkills[0].name)
})

test('M1.2: chain planner prompt carries active second-order canaries', () => {
  const prompt = chainPlannerPrompt({
    goal: 'defensive review',
    roundNo: 2,
    capabilityTier: 2,
    approvedOrigins: [fakeOrigin],
    activeFacts: [],
    coldDigests: [],
    chainSteps: [],
    secondOrderCanaries: [{
      marker: 'gn2o_deadbeef',
      status: 'surfaced',
      injectedOrigin: fakeOrigin,
      injectedEndpoint: '/profile',
      injectedParam: 'bio',
      injectedPersona: 'user_a',
      surfacedOrigin: fakeOrigin,
      surfacedEndpoint: '/admin/users',
      surfacedPersona: 'admin',
    }],
  })
  const parsed = JSON.parse(prompt) as { secondOrderCanaries: Array<{ marker: string; surfacedPersona: string | null }> }
  assert.equal(parsed.secondOrderCanaries.length, 1)
  assert.equal(parsed.secondOrderCanaries[0].marker, 'gn2o_deadbeef')
  assert.equal(parsed.secondOrderCanaries[0].surfacedPersona, 'admin')
})

// ============================================================================
// 1.3 Dedupe: all ReplaySpec kinds + (method, param) fingerprints
// ============================================================================

test('M1.3: the three previously-collapsing spec kinds extract their real target route', () => {
  const auth = declarativeReplaySpecSchema.parse({
    ...baseReplayFields(fakeOrigin),
    kind: 'auth_protocol_proof',
    protocol: 'jwt',
    steps: [
      { id: 'ctrl', role: 'control', description: 'Reject invalid token', request: { origin: fakeOrigin, method: 'GET', pathAndQuery: '/api/me' } },
      { id: 'prb', role: 'probe', description: 'Accept mutated token', request: { origin: fakeOrigin, method: 'GET', pathAndQuery: '/api/session/refresh', persona: 'user_a', authMutation: { kind: 'alg_none' } } },
    ],
  })
  const authFields = extractSpecDedupeFields(auth)
  assert.equal(authFields.endpoint, '/api/session/refresh')
  assert.equal(authFields.method, 'GET')
  assert.equal(authFields.param, 'auth:alg_none')
  assert.equal(authFields.authState, 'persona:user_a')

  const cache = declarativeReplaySpecSchema.parse({
    ...baseReplayFields('https://cdn.example.invalid'),
    origin: 'https://cdn.example.invalid',
    kind: 'cache_differential',
    targetOrigin: 'https://cdn.example.invalid',
    controlPath: '/pricing?_gcb=0123456789abcdef0123456789abcdef',
    probePath: '/pricing/private?_gcb=fedcba9876543210fedcba9876543210',
    poisonHeaders: { 'X-Forwarded-Host': 'cdn-canary.invalid' },
  })
  const cacheFields = extractSpecDedupeFields(cache)
  assert.equal(cacheFields.endpoint, '/pricing/private?_gcb=fedcba9876543210fedcba9876543210')
  assert.equal(cacheFields.method, 'GET')
  assert.equal(cacheFields.param, 'x-forwarded-host')

  const timing = declarativeReplaySpecSchema.parse({
    ...baseReplayFields(fakeOrigin),
    kind: 'sql_time_diff',
    targetOrigin: fakeOrigin,
    method: 'GET',
    pathAndQuery: '/reports?sort=name',
    paramName: 'sort',
    paramLocation: 'query',
  })
  const timingFields = extractSpecDedupeFields(timing)
  assert.equal(timingFields.endpoint, '/reports?sort=name')
  assert.equal(timingFields.method, 'GET')
  assert.equal(timingFields.param, 'sort')
})

test('M1.3: all 14 ReplaySpec kinds keep distinct routes (only TLS is intentionally origin-wide)', () => {
  const specs: Array<{ kind: string; spec: Record<string, unknown>; expected: string }> = [
    { kind: 'http_chain', expected: '/api/orders/1?expand=owner', spec: { kind: 'http_chain', steps: [
      { role: 'control', request: { pathAndQuery: '/api/orders/1', persona: 'user_a', method: 'GET' } },
      { role: 'probe', request: { pathAndQuery: '/api/orders/1?expand=owner', persona: 'user_b', method: 'GET' } },
    ] } },
    { kind: 'dns_takeover', expected: '/assets/health', spec: { kind: 'dns_takeover', probePath: '/assets/health' } },
    { kind: 'tls_audit', expected: '/', spec: { kind: 'tls_audit' } },
    { kind: 'browser_dom', expected: '/search', spec: { kind: 'browser_dom', probePath: '/search', persona: 'user_a' } },
    { kind: 'browser_chain', expected: '/inbox?msg=1', spec: { kind: 'browser_chain', steps: [
      { role: 'control', pathAndQuery: '/inbox', persona: 'user_a' },
      { role: 'probe', pathAndQuery: '/inbox?msg=1', persona: 'user_b' },
    ] } },
    { kind: 'race_burst', expected: '/redeem', spec: { kind: 'race_burst', burst: [{ pathAndQuery: '/redeem', persona: 'user_a', method: 'POST' }] } },
    { kind: 'rce_proof', expected: '/tools/ping', spec: { kind: 'rce_proof', probeStep: { request: { pathAndQuery: '/tools/ping', method: 'POST', persona: 'user_a', jsonBody: { host: 'x' } } } } },
    { kind: 'sql_boolean_diff', expected: '/products', spec: { kind: 'sql_boolean_diff', pathAndQuery: '/products', method: 'GET', paramName: 'filter', persona: 'user_a' } },
    { kind: 'ws_chain', expected: '/socket', spec: { kind: 'ws_chain', steps: [
      { role: 'control', pathAndQuery: '/socket', persona: 'user_a' },
      { role: 'probe', pathAndQuery: '/socket', persona: 'user_b' },
    ] } },
    { kind: 'upload_probe', expected: '/files', spec: { kind: 'upload_probe', uploadStep: { pathAndQuery: '/files', method: 'POST', persona: 'user_a', fieldName: 'file' } } },
    { kind: 'static_ast_proof', expected: '/repo/src/db.ts', spec: { kind: 'static_ast_proof', repo: 'repo', file: 'src/db.ts', startLine: 42 } },
    { kind: 'auth_protocol_proof', expected: '/api/me', spec: { kind: 'auth_protocol_proof', steps: [
      { role: 'control', request: { pathAndQuery: '/api/me' } },
      { role: 'probe', request: { pathAndQuery: '/api/me', persona: 'user_a', method: 'GET', authMutation: { kind: 'strip_signature' } } },
    ] } },
    { kind: 'cache_differential', expected: '/assets/app.js', spec: { kind: 'cache_differential', probePath: '/assets/app.js', method: 'GET' } },
    { kind: 'sql_time_diff', expected: '/reports', spec: { kind: 'sql_time_diff', pathAndQuery: '/reports', method: 'GET', paramName: 'sort' } },
  ]

  const hashes = new Set<string>()
  for (const { kind, spec, expected } of specs) {
    const fields = extractSpecDedupeFields(spec)
    assert.equal(fields.specKind, kind)
    assert.equal(fields.endpoint, expected, `${kind} endpoint must not collapse to '/'`)
    const fp = computeFindingFingerprint({
      origin: fakeOrigin,
      cwe: 'CWE-89',
      endpoint: fields.endpoint,
      authState: fields.authState,
      specKind: fields.specKind,
      method: fields.method,
      param: fields.param,
    })
    hashes.add(fp.hash)
  }
  assert.equal(hashes.size, specs.length, 'every ReplaySpec kind must produce a distinct fingerprint')
})

test('M1.3: fingerprints distinguish HTTP method and primary parameter on the same route', () => {
  const base = { origin: fakeOrigin, cwe: 'CWE-639', endpoint: '/api/invoices/1001', authState: 'persona:user_b', specKind: 'http_chain' }
  const get = computeFindingFingerprint({ ...base, method: 'GET' })
  const del = computeFindingFingerprint({ ...base, method: 'DELETE' })
  assert.notEqual(get.hash, del.hash)
  assert.ok(get.key.includes('|GET|'))
  assert.ok(del.key.includes('|DELETE|'))

  const paramA = computeFindingFingerprint({ ...base, method: 'GET', param: 'sort' })
  const paramB = computeFindingFingerprint({ ...base, method: 'GET', param: 'filter' })
  assert.notEqual(paramA.hash, paramB.hash)

  // Findings without an explicit method/param must not fragment: both default to ANY/''.
  const anonymousA = computeFindingFingerprint(base)
  const anonymousB = computeFindingFingerprint({ ...base, method: null, param: null })
  assert.equal(anonymousA.hash, anonymousB.hash)

  // Structural dedupe honours the method split even on the same normalized endpoint.
  const dup = checkStructuralDuplicate(
    { origin: fakeOrigin, title: 'Delete another tenant invoice', cwe: 'CWE-639', category: 'broken-access-control', severity: 'high', endpoint: '/api/invoices/2002', authState: 'persona:user_b', specKind: 'http_chain', method: 'DELETE' },
    [{ id: 'f-get', origin: fakeOrigin, title: 'Read another tenant invoice', status: 'confirmed', cwe: 'CWE-639', category: 'broken-access-control', severity: 'high', endpoint: '/api/invoices/1001', authState: 'persona:user_b', specKind: 'http_chain', method: 'GET' }],
  )
  assert.equal(dup.isDuplicate, false)
})

// ============================================================================
// 1.2 Second-order canary correlation
// ============================================================================

async function seedRunWithWorker(storage: Store) {
  const { runId, run, assetIds } = await setupApprovedRun(storage, {
    environment: 'local-lab',
    seeds: ['http://127.0.0.1:9'],
  })
  const detail = storage.runDetail(runId)
  const asset = detail.run.candidates.find(c => c.id === assetIds[0])!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Canary correlation', 'Second-order canary probe step.', {
    sourceOrigins: [asset.origin],
  })
  return { runId, run, asset, worker }
}

function countSecondOrderSurfaceFacts(storage: Store, runId: string, marker: string): number {
  return storage.listFacts(runId, { includeTainted: true, limit: 500 })
    .filter(f => (f.kind as string) === 'second_order_surface' && String(f.data?.marker ?? '') === marker).length
}

test('M1.2: minted second-order canaries survive self-echo and keep tracking later surfaces', async (t) => {
  resetSecondOrderSurfaceTracking()
  const storage = makeStore(t)
  const { runId, worker } = await seedRunWithWorker(storage)
  const broker = new CanaryBroker({ storage })
  const origin = 'http://127.0.0.1:9'
  const minted = broker.mintSecondOrderCanary({
    runId,
    assignmentId: worker.id,
    injectedOrigin: origin,
    injectedEndpoint: '/profile',
    injectedParam: 'bio',
    injectedPersona: 'user_a',
    storage,
  })
  assert.match(minted.marker, /^gn2o_[a-f0-9]{8}$/)
  assert.ok(minted.httpUrl.includes(minted.marker))
  assert.ok(minted.dnsHost.startsWith(`${minted.marker}.`))
  assert.ok(minted.id)

  // 1) Benign self-echo by the injecting persona on the injecting route: never a surface.
  const self = scanSecondOrderMarkers({
    text: `{"bio":"${minted.marker}"}`,
    runId,
    assignmentId: worker.id,
    origin,
    endpoint: '/profile',
    persona: 'user_a',
    mediaType: 'application/json',
    storage,
  })
  assert.deepEqual(self, [])
  assert.equal(countSecondOrderSurfaceFacts(storage, runId, minted.marker), 0)
  assert.equal(storage.listSecondOrderCanaries(runId)[0].status, 'planted')

  // 2) Early benign cross-endpoint JSON echo surfaces once.
  scanSecondOrderMarkers({
    text: `{"echo":"${minted.marker}"}`,
    runId,
    assignmentId: worker.id,
    origin,
    endpoint: '/api/echo',
    persona: 'user_b',
    mediaType: 'application/json',
    exchangeId: 'ex-echo',
    storage,
  })
  assert.equal(countSecondOrderSurfaceFacts(storage, runId, minted.marker), 1)
  assert.equal(storage.listSecondOrderCanaries(runId)[0].status, 'surfaced')

  // 3) The regression: a later admin HTML render MUST still be detected after the row moved to
  //    `surfaced` (the old implementation only scanned status='planted').
  const adminHtml = scanSecondOrderMarkers({
    text: `<table><tr><td>${minted.marker}</td></tr></table>`,
    runId,
    assignmentId: worker.id,
    origin,
    endpoint: '/admin/users',
    persona: 'admin',
    mediaType: 'text/html',
    exchangeId: 'ex-admin',
    storage,
  })
  assert.equal(adminHtml.length, 1)
  assert.equal(countSecondOrderSurfaceFacts(storage, runId, minted.marker), 2)
  const surfaceFacts = storage.listFacts(runId, { includeTainted: true, limit: 500 })
    .filter(f => (f.kind as string) === 'second_order_surface')
  const adminFact = surfaceFacts.find(f => f.data?.surfacedEndpoint === '/admin/users')!
  assert.ok(adminFact)
  assert.equal(adminFact.data?.crossPersona, true)
  assert.equal(adminFact.data?.surfacedMediaType, 'text/html')
  const surfaces = adminFact.data?.surfaces as Array<Record<string, unknown>>
  assert.ok(Array.isArray(surfaces) && surfaces.length === 2, 'aggregated surfaces array must retain both hits')

  // 4) Re-observing the same surface is idempotent.
  const repeat = scanSecondOrderMarkers({
    text: `<p>${minted.marker}</p>`,
    runId,
    assignmentId: worker.id,
    origin,
    endpoint: '/admin/users',
    persona: 'admin',
    mediaType: 'text/html',
    storage,
  })
  assert.deepEqual(repeat, [])
  assert.equal(countSecondOrderSurfaceFacts(storage, runId, minted.marker), 2)

  // 5) A marker that was never minted for this run is ignored.
  const unknown = scanSecondOrderMarkers({
    text: 'gn2o_00000000',
    runId,
    assignmentId: worker.id,
    origin,
    endpoint: '/admin/users',
    persona: 'admin',
    storage,
  })
  assert.deepEqual(unknown, [])
})

test('M1.2: OOB callback bodies are captured bounded and redacted', async (t) => {
  const storage = makeStore(t)
  const { runId, worker } = await seedRunWithWorker(storage)
  const broker = new CanaryBroker({ storage })
  const info = await broker.startListener({ host: '127.0.0.1', port: 0 })
  t.after(() => broker.stopListener())
  assert.ok(info.port && info.port > 0)
  const minted = broker.mintSecondOrderCanary({
    runId,
    assignmentId: worker.id,
    injectedOrigin: 'https://target.example.invalid',
    injectedEndpoint: '/webhook',
    injectedParam: 'url',
    storage,
  })

  const secretLike = 'password=hunter2hunter2'
  const callbackBody = `${secretLike} marker=${minted.marker} ${'x'.repeat(6000)}`
  const status = await new Promise<number>((resolvePromise, reject) => {
    const req = httpRequest({
      host: '127.0.0.1',
      port: info.port!,
      method: 'POST',
      path: `/c/${minted.marker}`,
      headers: { 'content-type': 'application/json' },
    }, res => {
      res.resume()
      res.on('end', () => resolvePromise(res.statusCode ?? 0))
    })
    req.on('error', reject)
    req.end(callbackBody)
  })
  assert.equal(status, 200)

  // The listener appends the hit before responding, so it is visible immediately.
  const check = broker.checkCanary(minted.marker, { storage, runId })
  assert.equal(check.hit, true)
  const detail = check.detail as { bodyPreview?: string; bodyBytes?: number; method?: string } | null
  assert.equal(detail?.method, 'POST')
  assert.ok(detail?.bodyPreview, 'callback body preview must be captured')
  assert.ok(!detail!.bodyPreview!.includes('hunter2hunter2'), 'credential-like values must be redacted')
  assert.ok(detail!.bodyPreview!.length <= 4096 + 16, 'callback body preview must be bounded')
  assert.ok((detail!.bodyBytes ?? 0) > 4096, 'original byte count is recorded separately from the bounded preview')
})

// ============================================================================
// 1.1 Execution wiring (storage + grant + forwarded tool args)
// ============================================================================

test('M1.1: Execution attaches storage to broker, browser and grant, and mints via the canary broker', async (t) => {
  const storage = makeStore(t)
  const { run, asset, worker } = await seedRunWithWorker(storage)
  const execution = new Execution(storage)
  t.after(() => execution.stop())

  assert.equal(execution.broker.getStorage(), storage, 'RequestBroker must receive the run store')
  const browserOptions = (execution.browser as unknown as { options: { storage?: unknown } }).options
  assert.equal(browserOptions.storage, storage, 'ScopedBrowser must receive the run store')

  const job = {
    assignment: worker as Assignment,
    origins: new Set<string>(),
    controller: new AbortController(),
  }
  const built = (execution as unknown as {
    buildGrant: (job: unknown, run: Run, permitted: ReadonlySet<string>) => {
      grant: {
        storage?: unknown
        canaryBroker?: unknown
        scopeRevision?: number
        mintCanary?: (purpose: string, origin?: string) => { httpUrl?: string; url?: string } | null
      }
    }
  }).buildGrant(job, run, new Set([asset.origin]))
  assert.equal(built.grant.storage, storage)
  assert.ok(built.grant.canaryBroker instanceof CanaryBroker)
  assert.equal(built.grant.scopeRevision, run.scopeRevision)

  const minted = built.grant.mintCanary?.('m1-wiring', asset.origin)
  assert.ok(minted?.httpUrl?.includes('/c/'))
  const token = minted!.httpUrl!.split('/c/')[1]
  const check = execution.canaryBroker.checkCanary(token, { storage, runId: run.id })
  assert.equal(check.found, true, 'grant.mintCanary must register the token with the broker')
})

test('M1.1: all four brokered tool paths forward session/csrf/authMutation/trace/run/assignment ids', () => {
  const executeHttpBlock = /const runHttp = \(\) => host\.broker\.executeHttp\(\{[\s\S]{0,900}?\}, grant, signal\)/.exec(transportSource)?.[0] ?? ''
  assert.ok(executeHttpBlock, 'executeHttp call not found')
  for (const fragment of [
    'session: args.session',
    'csrfBind: args.csrfBind',
    'authMutation: args.authMutation',
    'probeClass: args.probeClass',
    'traceId: args.traceId',
    'runId: curRun.id',
    'assignmentId: job.assignment.id',
  ]) {
    assert.ok(executeHttpBlock.includes(fragment), `executeHttp must forward ${fragment}`)
  }

  const raceBlock = /const executeRaceBurstTool = async[\s\S]{0,2600}?host\.broker\.executeRaceBurst/.exec(transportSource)?.[0] ?? ''
  assert.ok(raceBlock)
  for (const fragment of ['session: r.session', 'csrfBind: r.csrfBind', 'authMutation: r.authMutation', 'traceId: r.traceId', 'runId: curRun.id', 'assignmentId: job.assignment.id']) {
    assert.ok(raceBlock.includes(fragment), `executeRaceBurstTool must forward ${fragment}`)
  }

  const batchBlock = /request_http_batch: async[\s\S]{0,1800}?host\.broker\.executeBatch/.exec(transportSource)?.[0] ?? ''
  assert.ok(batchBlock)
  for (const fragment of ['session: r.session', 'csrfBind: r.csrfBind', 'traceId: r.traceId', 'runId: curRun.id', 'assignmentId: job.assignment.id']) {
    assert.ok(batchBlock.includes(fragment), `request_http_batch must forward ${fragment}`)
  }

  const visitBlock = /browser_visit: async \(args, signal\) => \{[\s\S]{0,1200}?await host\.browser\.visitPage\(\{[\s\S]{0,4000}?\}, grant, signal\)/.exec(transportSource)?.[0] ?? ''
  assert.ok(visitBlock)
  for (const fragment of ['session: args.session', 'runId: curRun.id', 'assignmentId: job.assignment.id', 'traceId:']) {
    assert.ok(visitBlock.includes(fragment), `browser_visit must forward ${fragment}`)
  }

  // Broker/browser construction, transport delegation, and grant hydration.
  assert.ok(/return buildBrokeredTransportHandlers\(\{[\s\S]{0,500}?broker: this\.broker,[\s\S]{0,200}?browser: this\.browser,/.test(executionSource))
  assert.ok(/new ScopedBrowser\(this\.broker, \{ storage \}\)/.test(executionSource))
  assert.ok(/createBroker\(\{ storage, canaryBroker: this\.canaryBroker \}\)/.test(executionSource))
  assert.ok(/storage: this\.storage,\s*canaryBroker: this\.canaryBroker,/.test(executionSource))
})

test('M1.2: second-order scanning covers headers, bodies and WebSocket frames', () => {
  assert.ok(/scanSecondOrderExchange: \(run, aid, res, exId, mt\) => this\.scanSecondOrderExchange\(run, aid, res, exId, mt\)/.test(executionSource))
  assert.ok(/host\.scanSecondOrderExchange\(curRun, job\.assignment\.id, res, saved\.id\)/.test(transportSource))
  assert.ok(/host\.scanSecondOrderExchange\(curRun, job\.assignment\.id, ex, saved\.id\)/.test(transportSource))
  const wsBlock = /const wsScanText = \[[\s\S]{0,600}?mediaType: 'websocket'/.exec(transportSource)?.[0] ?? ''
  assert.ok(wsBlock, 'WebSocket frames + upgrade headers must be scanned for gn2o_ markers')
  assert.ok(/const headerText = Object\.entries\(res\.respHeaders \?\? \{\}\)/.test(executionSource), 'response headers must be scanned')
})

// ============================================================================
// 1.5 Enriched inline feedback + bounded Phase-3 refinement
// ============================================================================

function makeExchange(overrides: Partial<BrokerExchangeResult> = {}): BrokerExchangeResult {
  return {
    origin: fakeOrigin,
    finalOrigin: fakeOrigin,
    redirectOrigins: [],
    method: 'GET',
    pathAndQuery: '/account',
    personaHandle: 'user_a',
    status: 302,
    mediaType: 'text/html',
    reqHeaders: {},
    respHeaders: {
      'content-type': 'text/html; charset=utf-8',
      location: '/login?next=%2Faccount',
      'cache-control': 'no-store',
      'x-cache': 'MISS',
      age: '0',
      vary: 'Accept-Encoding',
      'access-control-allow-origin': fakeOrigin,
      'access-control-allow-credentials': 'true',
    },
    setCookies: [{ name: 'sid', secure: true, httpOnly: true, sameSite: 'Lax' }],
    bodyPreview: '',
    body: `<html>session=SUPERSECRETVALUE ${'x'.repeat(2000)}</html>`,
    bodySha256: 'sha',
    bodyBytes: 2048,
    bodyTruncated: false,
    durationMs: 12,
    observation: {} as never,
    ...overrides,
  }
}

test('M1.5: inline feedback carries exchange ids, key headers, bounded previews, vars and SQL rounds', () => {
  const secret = { value: 'SUPERSECRETVALUE', placeholder: '[redacted:secret]' }
  const exchange = makeExchange()
  const feedback = buildInlineVerifyFeedback(
    { kind: 'http_chain' },
    {
      verdict: 'dismissed',
      outcome: { confirmed: false, controlPassed: false, observed: 'HTTP 403', expected: 'HTTP 200', reason: 'Replay control step "ctrl" returned 403.' },
      exchangeIds: ['ex-1', 'ex-2'],
      exchanges: [exchange],
      evidencePayload: {
        kind: 'http_chain',
        steps: {
          ctrl: { id: 'ctrl', role: 'control', status: 302, mediaType: 'text/html', bodyBytes: 2048 },
          prb: { id: 'prb', role: 'probe', status: 403, mediaType: 'application/json', bodyBytes: 20 },
        },
        extractedVars: { sessionToken: 'SUPERSECRETVALUE', harmless: 'ok' },
      },
      evidenceSha256: 'evidence',
    },
    2,
    2,
    [secret],
  )

  assert.deepEqual(feedback.replayExchangeIds, ['ex-1', 'ex-2'])
  assert.equal(feedback.failedStepId, 'ctrl')
  const header = feedback.keyResponseHeaders?.[0]
  assert.ok(header)
  assert.equal(header.stepId, 'ctrl')
  assert.equal(header.status, 302)
  assert.equal(header.location, '/login?next=%2Faccount')
  assert.equal(header.cacheControl, 'no-store')
  assert.equal(header.xCache, 'MISS')
  assert.equal(header.age, '0')
  assert.equal(header.vary, 'Accept-Encoding')
  assert.equal(header.accessControl, 'access-control-allow-credentials: true; access-control-allow-origin: https://app.example.invalid')
  assert.deepEqual(header.setCookie, [{ name: 'sid', secure: true, httpOnly: true, sameSite: 'Lax' }])

  assert.ok(feedback.stepBodyPreviews && feedback.stepBodyPreviews.length >= 1)
  for (const preview of feedback.stepBodyPreviews ?? []) {
    assert.ok(preview.preview.length <= 513, 'previews are capped at 512 bytes plus an ellipsis')
    assert.ok(!preview.preview.includes('SUPERSECRETVALUE'), 'registered secrets never leak into previews')
  }
  const vars = feedback.extractedVars ?? []
  assert.deepEqual(vars.map(v => v.key).sort(), ['harmless', 'sessionToken'])
  assert.ok(!vars.find(v => v.key === 'sessionToken')!.preview.includes('SUPERSECRETVALUE'))
  assert.equal(feedback.verificationKind, 'http_chain')

  // The enrichment must survive JSON serialization used for DB + LLM transport.
  const roundTripped = JSON.parse(JSON.stringify(feedback)) as Record<string, unknown>
  assert.ok(roundTripped.replayExchangeIds)
  assert.ok(roundTripped.keyResponseHeaders)
  assert.ok(roundTripped.stepBodyPreviews)
})

test('M1.5: retired sql_boolean_diff and sql_time_diff feedback reports retired fail-closed verdict', () => {
  for (const kind of ['sql_boolean_diff', 'sql_time_diff'] as const) {
    const feedback = buildInlineVerifyFeedback(
      { kind },
      {
        verdict: 'dismissed',
        outcome: {
          confirmed: false,
          controlPassed: false,
          observed: 'retired_legacy_spec_kind: use kovo_verify',
          expected: 'Proof submitted via kovo_verify or a wired floor recipe.',
          reason: 'retired_legacy_spec_kind: use kovo_verify',
        },
        exchangeIds: [],
        exchanges: [],
        evidencePayload: { kind, retired: true, reason: 'retired_legacy_spec_kind: use kovo_verify' },
        evidenceSha256: 'e',
      },
      1,
      2,
    )
    assert.equal(feedback.verdict, 'dismissed')
    assert.equal(feedback.controlPassed, false)
    assert.equal(feedback.verificationKind, kind)
    assert.match(feedback.assertionSummary?.reason ?? '', /retired_legacy_spec_kind/i)
  }
})

test('M0: Phase-3 DSL refinement queues are retired from execution.ts', () => {
  // v7 M0 cut 1: the bounded Phase-3 reasoning pass existed only to repair a broken declarative
  // spec. Agents prove with executable scripts now, so neither the eligibility queue nor the
  // refine:<specId> worker lane may remain wired into the engine.
  assert.ok(!executionSource.includes('refinementEligible'))
  assert.ok(!executionSource.includes('maxPhase3RefinementJobs'))
  assert.ok(!executionSource.includes('runPhase3RefinementJob'))
  assert.ok(!executionSource.includes('markRefinementEligible'))
  assert.ok(!/stepId: `refine:/.test(executionSource))
  assert.ok(!executionSource.includes('Phase-3 refinement'))
})

test('M1: project schema helper stays usable (guards against accidental import drift)', () => {
  const project = newProject.parse({
    requestId: randomUUID(),
    name: 'm1 core fixture project',
    seeds: [fakeOrigin],
    environment: 'public',
  })
  assert.ok(project)
  assert.equal(project.environment, 'public')
})

// ============================================================================
// M1 fallback: bounded deterministic investigation when no model profile exists
// ============================================================================

test('M1 fallback: zero model profiles probe discovered endpoints and propose deterministic findings', async (t) => {
  // Fixture behaves like a boolean-differential SQL sink for the numeric comparison style.
  const fx = await startHttpFixture(t, (req, _body, res) => {
    const url = new URL(req.url ?? '/', 'http://fixture.invalid')
    const q = url.searchParams.get('q') ?? ''
    const match = /AND\s+(\d+)\s*=\s*(\d+)/.exec(q)
    const rows = match && match[1] !== match[2] ? [] : [{ id: 1 }, { id: 2 }]
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ rows }))
  })
  const storage = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 200, tier: 2 })
  const endpoint = storage.upsertEndpoint({
    runId,
    origin: fx.origin,
    method: 'GET',
    pathTemplate: '/search?q=',
    source: 'openapi',
    riskScore: 70,
  })
  storage.upsertEndpointParam({
    runId,
    endpointId: endpoint.id,
    name: 'q',
    location: 'query',
    source: 'openapi',
  })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })

  const execution = new Execution(storage)
  t.after(() => execution.stop())
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
    (execution as unknown as { runDeterministicInvestigation: (run: Run) => Promise<void> })
      .runDeterministicInvestigation(storage.run(runId)))

  const detail = storage.runDetail(runId)
  assert.ok(detail.exchangesSummary.length >= 4, `expected real brokered probes to run (got ${detail.exchangesSummary.length} exchanges)`)
  assert.ok(detail.exchangesSummary.every(ex => ex.origin === fx.origin))

  const specs = detail.replaySpecs.filter(row => row.spec.kind === 'sql_boolean_diff')
  assert.equal(specs.length, 1, 'one deterministic sql_boolean_diff spec must be proposed')
  const finding = detail.findings.find(f => f.replaySpecId === specs[0].id)
  assert.ok(finding, 'the deterministic spec must be attached to a pending finding')
  assert.equal(finding!.status, 'pending')
  assert.equal(finding!.cwe, 'CWE-89')

  const verifyWorkers = storage.workerList(runId).filter(w => w.phase === 'verification' && w.stepId === specs[0].id)
  assert.equal(verifyWorkers.length, 1, 'normal Zero-LLM verification queue must receive the deterministic spec')

  const facts = storage.listFacts(runId, { includeTainted: false, limit: 100 })
  assert.ok(facts.some(f => f.data?.subkind === 'differential_anomaly'), 'the differential signal must be recorded as a fact')
  assert.ok(storage.eventsAfter(runId, 0).some(e => e.kind === 'deterministic_probes.summary'))
})

test('M1 fallback: deterministic mode respects request budget and never runs destructive methods', async (t) => {
  const fx = await startHttpFixture(t, (_req, _body, res) => {
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ rows: [{ id: 1 }] }))
  })
  const storage = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 8, tier: 2 })
  const endpoint = storage.upsertEndpoint({
    runId,
    origin: fx.origin,
    method: 'DELETE',
    pathTemplate: '/items/{{id}}',
    source: 'openapi',
    riskScore: 90,
  })
  storage.upsertEndpointParam({ runId, endpointId: endpoint.id, name: 'id', location: 'path', source: 'openapi' })

  const execution = new Execution(storage)
  t.after(() => execution.stop())
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () =>
    (execution as unknown as { runDeterministicInvestigation: (run: Run) => Promise<void> })
      .runDeterministicInvestigation(storage.run(runId)))

  const detail = storage.runDetail(runId)
  assert.equal(detail.exchangesSummary.filter(ex => ex.method === 'DELETE').length, 0, 'DELETE endpoints must never be probed')
  assert.ok(detail.exchangesSummary.length <= 16, 'request cap must bound the deterministic pass')
})

test('M1 fallback: the agentic path is untouched when a model profile exists', async (t) => {
  const storage = makeStore(t)
  const { runId, run } = await setupApprovedRun(storage, { seeds: [fakeOrigin] })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const execution = new Execution(storage)
  t.after(() => execution.stop())

  const privateExec = execution as unknown as {
    driveInvestigation: (run: Run, profiles: readonly unknown[]) => void
    deterministicInFlight: Set<string>
    deterministicCompleted: Set<string>
  }
  privateExec.driveInvestigation(storage.run(runId), [{ id: 'mock-profile' }])

  assert.equal(privateExec.deterministicInFlight.size, 0, 'profile-backed runs must not enter deterministic mode')
  assert.equal(privateExec.deterministicCompleted.size, 0)
  assert.equal(storage.workerList(runId).filter(w => w.title.includes('Deterministic differential probes')).length, 0)
})

// ============================================================================
// Precision: vertical BFLA requires impact (not a read-only 2xx)
// ============================================================================

function bflaSpec(overrides: { cwe?: string; probeMethod?: string; titles?: string } = {}) {
  return {
    version: 1 as const,
    kind: 'http_chain' as const,
    origin: fakeOrigin,
    title: overrides.titles ?? 'Viewer role can access admin endpoint',
    category: 'broken-access-control',
    cwe: overrides.cwe ?? 'CWE-285',
    severity: 'high' as const,
    severityRationale: 'A viewer reached a function reserved for administrators.',
    impact: 'Vertical privilege escalation.',
    remediation: 'Enforce a role/function authorization check before the handler runs.',
    recheckInstructions: 'Replay the actor matrix after the fix.',
    spaCatchallControl: false,
    assertionsJq: '{ controlPassed: (.steps.ctrl.status == 200), confirmed: (.steps.prb.status == 200), observed: "ok", expected: "denied" }',
    steps: [
      { id: 'ctrl', role: 'control' as const, description: 'Admin call', request: { origin: fakeOrigin, method: 'GET' as const, pathAndQuery: '/api/admin/auditlogs', persona: 'admin', followRedirects: false } },
      { id: 'prb', role: 'probe' as const, description: 'Viewer call', request: { origin: fakeOrigin, method: (overrides.probeMethod ?? 'GET') as 'GET', pathAndQuery: '/api/admin/auditlogs', persona: 'viewer', followRedirects: false } },
    ],
  }
}

test('M1 precision: read-only BFLA with only a 2xx cannot confirm (impact gate)', () => {
  const spec = bflaSpec()
  // Both admin and viewer are allowed to read this route (the reported false positive).
  const flat = assessBflaImpact(spec, {
    ctrl: { id: 'ctrl', role: 'control', status: 200, method: 'GET', pathAndQuery: '/api/admin/auditlogs', body: '{"rows":[1,2,3,4,5,6,7,8]}' },
    prb: { id: 'prb', role: 'probe', status: 200, method: 'GET', pathAndQuery: '/api/admin/auditlogs', body: '{"rows":[1,2,3,4,5,6,7,8]}' },
  })
  assert.equal(flat.required, true)
  assert.equal(flat.satisfied, false)
  assert.match(flat.reason, /lacks impact evidence/i)
})

test('M1 precision: BFLA confirms with a denied sibling actor or a persisted privileged mutation', () => {
  const spec = bflaSpec()
  const differential = assessBflaImpact(spec, {
    ctrl: { id: 'ctrl', role: 'control', status: 403, method: 'GET', pathAndQuery: '/api/admin/auditlogs', body: '{"error":"forbidden"}' },
    prb: { id: 'prb', role: 'probe', status: 200, method: 'GET', pathAndQuery: '/api/admin/auditlogs', body: '{"rows":[{"owner":"admin-user","action":"delete-user","target":"user-42"},{"owner":"admin-user","action":"rotate-key"}]}' },
  })
  assert.equal(differential.required, true)
  assert.equal(differential.satisfied, true)
  assert.match(differential.reason, /admin|below|disclos|differential/i)

  const mutatingSpec = {
    ...bflaSpec({ probeMethod: 'DELETE', cwe: 'CWE-269' }),
    requiredRole: 'admin' as const,
    steps: [
      { id: 'before', role: 'control' as const, description: 'Read the target user', request: { origin: fakeOrigin, method: 'GET' as const, pathAndQuery: '/api/admin/users/42', persona: 'admin', followRedirects: false } },
      { id: 'ctrl', role: 'control' as const, description: 'Admin call', request: { origin: fakeOrigin, method: 'GET' as const, pathAndQuery: '/api/admin/users', persona: 'admin', followRedirects: false } },
      { id: 'prb', role: 'probe' as const, description: 'Viewer delete', request: { origin: fakeOrigin, method: 'DELETE' as const, pathAndQuery: '/api/admin/users/42', persona: 'viewer', followRedirects: false } },
      { id: 'after', role: 'control' as const, description: 'Read the target user after the mutation', request: { origin: fakeOrigin, method: 'GET' as const, pathAndQuery: '/api/admin/users/42', persona: 'admin', followRedirects: false } },
    ],
    assertionsJq: '{ controlPassed: (.steps.ctrl.status == 200), confirmed: (.steps.prb.status == 204), observed: "deleted", expected: "denied" }',
  }
  // A 2xx mutation alone is not impact: the actor must be below the required role *and* a clean
  // readback must show the row was actually removed.
  const mutation = assessBflaImpact(mutatingSpec as never, {
    before: { status: 200, method: 'GET', pathAndQuery: '/api/admin/users/42', body: '{"id":42,"role":"member"}' },
    ctrl: { status: 200, method: 'GET', pathAndQuery: '/api/admin/users' },
    prb: { status: 204, method: 'DELETE', pathAndQuery: '/api/admin/users/42', body: '' },
    after: { status: 404, method: 'GET', pathAndQuery: '/api/admin/users/42', body: '{"error":"not_found"}' },
  })
  assert.equal(mutation.required, true)
  assert.equal(mutation.satisfied, true)
  assert.match(mutation.reason, /removed|persisted|below/i)

  const echoOnly = assessBflaImpact({ ...mutatingSpec, steps: mutatingSpec.steps.filter(step => step.id !== 'before' && step.id !== 'after') } as never, {
    ctrl: { status: 200, method: 'GET', pathAndQuery: '/api/admin/users' },
    prb: { status: 204, method: 'DELETE', pathAndQuery: '/api/admin/users/42', body: '' },
  })
  assert.equal(echoOnly.required, true)
  assert.equal(echoOnly.satisfied, false)
  assert.match(echoOnly.reason, /readback|persist|echo/i)

  const failedMutation = assessBflaImpact(mutatingSpec as never, {
    before: { status: 200, method: 'GET', pathAndQuery: '/api/admin/users/42', body: '{"id":42,"role":"member"}' },
    ctrl: { status: 200, method: 'GET', pathAndQuery: '/api/admin/users' },
    prb: { status: 403, method: 'DELETE', pathAndQuery: '/api/admin/users/42', body: '{"error":"forbidden"}' },
    after: { status: 200, method: 'GET', pathAndQuery: '/api/admin/users/42', body: '{"id":42,"role":"member"}' },
  })
  assert.equal(failedMutation.satisfied, false)
})

test('M1 precision: object-level BOLA (CWE-639) is not gated by the BFLA impact rule', () => {
  const bola = {
    ...bflaSpec(),
    cwe: 'CWE-639',
    title: 'Cross-tenant invoice read',
    impact: 'Horizontal data exposure.',
  }
  const assessment = assessBflaImpact(bola as never, {
    ctrl: { status: 200, method: 'GET', pathAndQuery: '/api/invoices/1', body: '{"id":1}' },
    prb: { status: 200, method: 'GET', pathAndQuery: '/api/invoices/1', body: '{"id":1}' },
  })
  assert.equal(assessment.required, false)
  assert.equal(assessment.satisfied, true)
})

test('M1 precision: BFLA gate feeds the verdict and survives feedback enrichment', () => {
  assert.ok(/const bflaImpact = assessBflaImpact\(spec, stepsOut\)/.test(
    readFileSync(join(repoRoot, 'src/server/replay-verifier.ts'), 'utf8')))
  assert.ok(/forcedInconclusiveReason = bflaImpact\.reason/.test(
    readFileSync(join(repoRoot, 'src/server/replay-verifier.ts'), 'utf8')))
  const feedback = buildInlineVerifyFeedback(
    { kind: 'http_chain' },
    {
      verdict: 'inconclusive',
      outcome: { confirmed: false, controlPassed: false, observed: 'viewer 200', expected: 'viewer denied', reason: 'Read-only BFLA proof lacks impact evidence.' },
      exchangeIds: [],
      exchanges: [],
      evidencePayload: { kind: 'http_chain', bflaImpact: { required: true, satisfied: false, reason: 'lacks impact' } },
      evidenceSha256: 'e',
    },
    1,
    2,
  )
  assert.equal(feedback.bflaImpactRequired, true)
  assert.equal(feedback.impactEvidenceMissing, true)
})

// ============================================================================
// Worker reliability: real Docker cause surfaced + failed containers removed
// ============================================================================

test('M1 worker reliability: docker failures report the real cause and never the bare image hint', async (t) => {
  const withDetail = formatWorkerFailure('docker: Error response from daemon: No such image: kovo-missing:v5\nsecond line', 125)
  assert.match(withDetail, /No such image/)
  assert.match(withDetail, /exit 125/)
  assert.match(withDetail, /Build the local worker image/)
  assert.ok(withDetail.length <= 520)
  const bare = formatWorkerFailure('', 1)
  assert.match(bare, /exit 1/)
  assert.match(bare, /Build the local worker image/)

  const dir = mkdtempSync(join(tmpdir(), 'kovo-v5-worker-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })
  const backend = new LinuxWorkerBackend({
    image: 'kovo-m1-missing-image:v5',
    workspace: { id: storage.workspace.id, directory: storage.directory },
  })
  let message = ''
  try {
    await backend.run(
      { assignmentId: randomUUID(), files: [], command: 'true', outputs: [] },
      AbortSignal.timeout(30_000),
    )
  } catch (error) {
    message = error instanceof Error ? error.message : String(error)
  }
  assert.ok(message.length > 0, 'a missing worker image must fail loudly')
  assert.notEqual(message, 'The isolated worker failed. Build the local worker image and check Docker availability.')
  assert.match(message, /isolated worker failed|Docker Unix socket|ENOENT|docker/i)
  await backend.reclaimInactive().catch(() => undefined)
})

// ============================================================================
// M4 hand-off wiring (templates, Stage-1 LLM, SCA CVEs, Patch Gate 6)
// ============================================================================

test('M4 wiring: safe templates receive CVE hypotheses and recon-discovered dynamic paths', () => {
  assert.match(transportSource, /const cveIds = \[\.\.\.new Set\(/)
  assert.match(transportSource, /kind: 'cve_hypothesis'/)
  assert.match(transportSource, /templateIdsForCves\(cveIds\)/)
  assert.match(transportSource, /discoveredPaths: \{ protectedPaths, apiPaths \}/)
  assert.ok(transportSource.includes('(admin|account|billing|settings|invoice|dashboard)'))
  assert.ok(transportSource.includes('^\\/(api|graphql|trpc)'))
  assert.ok(templateIdsForCves(['CVE-2025-29927']).includes('nextjs-middleware-subrequest-bypass'), 'curated CVE→template mapping must resolve')
})

test('M4 wiring: Stage-1 LLM is enabled by default and receives live endpoints', () => {
  assert.ok(!executionSource.includes('enableStage1Llm: false'))
  assert.match(executionSource, /enableStage1Llm: process\.env\.KOVO_STAGE1_LLM !== '0'/)
  assert.match(executionSource, /liveEndpoints: this\.storage\.listEndpoints\(run\.id\)/)
})

test('M4 wiring: dependency correlation iterates all parsed packages with curated-advisory annotation', () => {
  assert.ok(!executionSource.includes('highSignalPkgs') && !transportSource.includes('highSignalPkgs'), 'the JS-only high-signal allowlist must be gone')
  assert.match(executionSource, /hasCuratedAdvisory\(dep\.ecosystem, dep\.package\)/)
  assert.match(transportSource, /trivy-fs flagged \$\{cve\}/)
  assert.match(transportSource, /templateIds: templateIdsForCves\(\[cve\]\)/)
})

test('M4 wiring: Patch Gate 6 passes labRetest with an authorized baseline caller', () => {
  assert.match(executionSource, /const labHandle = this\.getLabTargetHandle\(run\.id\)/)
  assert.match(executionSource, /labRunner: this\.labRunner,[\s\S]{0,900}?baselineExpectStatus: \[200, 201, 204\]/)
  assert.ok(executionSource.includes('...(labRetest ? { labRetest } : {}),'))
})
