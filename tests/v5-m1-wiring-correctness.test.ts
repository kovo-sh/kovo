/**
 * Guardian v5 M1-core: P0 wiring, canary correlation, dedupe, routing & feedback correctness.
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
import { buildInlineVerifyFeedback } from '../src/server/replay-verifier.ts'
import type { BrokerExchangeResult } from '../src/server/broker.ts'
import { loadSkill, listSkills, selectPreInjectionSkills } from '../src/server/skills.ts'
import { Store } from '../src/server/store.ts'
import type { Assignment, Run } from '../src/server/store.ts'
import { setupApprovedRun, startHttpFixture, withEnv } from './v4-tier-helpers.ts'

const repoRoot = resolve(new URL('..', import.meta.url).pathname)
const executionSource = readFileSync(join(repoRoot, 'src/server/execution.ts'), 'utf8')
const fakeOrigin = 'https://app.example.invalid'

function makeStore(t: { after: (fn: () => void) => void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-v5-m1-'))
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
  const executeHttpBlock = /const runHttp = \(\) => this\.broker\.executeHttp\(\{[\s\S]{0,900}?\}, grant, signal\)/.exec(executionSource)?.[0] ?? ''
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

  const raceBlock = /const executeRaceBurstTool = async[\s\S]{0,2600}?this\.broker\.executeRaceBurst/.exec(executionSource)?.[0] ?? ''
  assert.ok(raceBlock)
  for (const fragment of ['session: r.session', 'csrfBind: r.csrfBind', 'authMutation: r.authMutation', 'traceId: r.traceId', 'runId: curRun.id', 'assignmentId: job.assignment.id']) {
    assert.ok(raceBlock.includes(fragment), `executeRaceBurstTool must forward ${fragment}`)
  }

  const batchBlock = /request_http_batch: async[\s\S]{0,1800}?this\.broker\.executeBatch/.exec(executionSource)?.[0] ?? ''
  assert.ok(batchBlock)
  for (const fragment of ['session: r.session', 'csrfBind: r.csrfBind', 'traceId: r.traceId', 'runId: curRun.id', 'assignmentId: job.assignment.id']) {
    assert.ok(batchBlock.includes(fragment), `request_http_batch must forward ${fragment}`)
  }

  const visitBlock = /browser_visit: async \(args, signal\) => \{[\s\S]{0,1200}?await this\.browser\.visitPage\(\{[\s\S]{0,4000}?\}, grant, signal\)/.exec(executionSource)?.[0] ?? ''
  assert.ok(visitBlock)
  for (const fragment of ['session: args.session', 'runId: curRun.id', 'assignmentId: job.assignment.id', 'traceId:']) {
    assert.ok(visitBlock.includes(fragment), `browser_visit must forward ${fragment}`)
  }

  // Broker/browser construction and grant hydration.
  assert.ok(/new ScopedBrowser\(this\.broker, \{ storage \}\)/.test(executionSource))
  assert.ok(/createBroker\(\{ storage, canaryBroker: this\.canaryBroker \}\)/.test(executionSource))
  assert.ok(/storage: this\.storage,\s*canaryBroker: this\.canaryBroker,/.test(executionSource))
})

test('M1.2: second-order scanning covers headers, bodies and WebSocket frames', () => {
  assert.ok(/scanSecondOrderExchange\(curRun, job\.assignment\.id, res, saved\.id\)/.test(executionSource))
  assert.ok(/scanSecondOrderExchange\(curRun, job\.assignment\.id, ex, saved\.id\)/.test(executionSource))
  const wsBlock = /const wsScanText = \[[\s\S]{0,600}?mediaType: 'websocket'/.exec(executionSource)?.[0] ?? ''
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

test('M1.5: sql_boolean_diff and sql_time_diff report every round summary', () => {
  const booleanFeedback = buildInlineVerifyFeedback(
    { kind: 'sql_boolean_diff' },
    {
      verdict: 'inconclusive',
      outcome: { confirmed: false, controlPassed: true, observed: 'no divergence', expected: 'divergence', reason: 'Boolean differential did not hold across all 3 randomized rounds.' },
      exchangeIds: [],
      exchanges: [],
      evidencePayload: {
        kind: 'sql_boolean_diff',
        sqlDiff: {
          passed: false,
          controlPassed: true,
          rounds: [
            { round: 1, pass: true, baseline: { status: 200 }, true: { status: 200 }, false: { status: 404 }, similarityBaselineTrue: 0.97, similarityTrueFalse: 0.2 },
            { round: 2, pass: false, baseline: { status: 200 }, true: { status: 404 }, false: { status: 404 }, similarityBaselineTrue: 0.1, similarityTrueFalse: 1 },
            { round: 3, pass: false, baseline: { status: 200 }, true: { status: 500 }, false: { status: 500 }, similarityBaselineTrue: 0.05, similarityTrueFalse: 0.99 },
          ],
        },
      },
      evidenceSha256: 'e',
    },
    1,
    2,
  )
  assert.equal(booleanFeedback.sqlRoundSummaries?.length, 3)
  assert.equal(booleanFeedback.sqlRoundSummaries?.[0].pass, true)
  assert.equal(booleanFeedback.sqlRoundSummaries?.[1].trueStatus, 404)
  assert.equal(booleanFeedback.sqlRoundSummaries?.[2].falseStatus, 500)

  const timingFeedback = buildInlineVerifyFeedback(
    { kind: 'sql_time_diff' },
    {
      verdict: 'inconclusive',
      outcome: { confirmed: false, controlPassed: true, observed: 'no delay', expected: 'delay', reason: 'Timing differential below threshold.' },
      exchangeIds: [],
      exchanges: [],
      evidencePayload: {
        kind: 'sql_time_diff',
        sqlTimeDiff: {
          rounds: [
            { round: 1, baseline: { status: 200 }, delayProbe: { status: 200 }, baselineMs: 12, probeMs: 40 },
            { round: 2, baseline: { status: 200 }, delayProbe: { status: 200 }, baselineMs: 11, probeMs: 38 },
          ],
        },
      },
      evidenceSha256: 'e',
    },
    1,
    2,
  )
  assert.equal(timingFeedback.sqlRoundSummaries?.length, 2)
  assert.equal(timingFeedback.sqlRoundSummaries?.[0].delayProbeStatus, 200)
  assert.equal(timingFeedback.sqlRoundSummaries?.[0].probeMs, 40)
})

test('M1.5: Phase-3 refinement is gated by strong pre-signals and a hard <=10 job cap', async (t) => {
  const storage = makeStore(t)
  const { run, asset, worker } = await seedRunWithWorker(storage)
  const execution = new Execution(storage)
  t.after(() => execution.stop())

  const privateExec = execution as unknown as {
    hasStrongPreVerificationSignal: (
      run: Run,
      row: { finding: Finding },
      specRow: { spec: { kind: string } },
      feedback?: unknown,
    ) => boolean
    markRefinementEligible: (runId: string, specId: string) => void
    isRefinementEligible: (runId: string, specId: string) => boolean
    refinementBudgetRemaining: (runId: string) => number
  }

  const weakFinding = { finding: { status: 'inconclusive' } as Finding }
  // A plain http_chain with a failed control and no linked evidence is NOT worth an LLM pass.
  assert.equal(privateExec.hasStrongPreVerificationSignal(run, weakFinding, { spec: { kind: 'http_chain' } }, { controlPassed: false }), false)
  // A differential kind whose control passed is.
  assert.equal(privateExec.hasStrongPreVerificationSignal(run, weakFinding, { spec: { kind: 'sql_boolean_diff' } }, { controlPassed: true }), true)
  // A triggered canary is.
  assert.equal(privateExec.hasStrongPreVerificationSignal(run, weakFinding, { spec: { kind: 'http_chain' } }, { controlPassed: false, canaryTriggered: true }), true)
  // Static-only proofs never consume refinement budget.
  assert.equal(privateExec.hasStrongPreVerificationSignal(run, weakFinding, { spec: { kind: 'static_ast_proof' } }, { controlPassed: true }), false)

  // Linked SAST suspects count as strong pre-signals.
  storage.addFact(run, worker, {
    kind: 'code_audit_suspect',
    origin: asset.origin,
    summary: 'Suspect sink without an ownership predicate.',
    data: { subkind: 'code_audit_suspect', repo: 'r', file: 'a.ts', line: 1, sinkKind: 'api_route' },
  })
  const suspectFactId = storage.listFacts(run.id, { includeTainted: false, limit: 50 })[0].id
  assert.equal(privateExec.hasStrongPreVerificationSignal(
    run,
    { finding: { status: 'inconclusive', chainFactIds: [suspectFactId] } as Finding },
    { spec: { kind: 'http_chain' } },
    { controlPassed: false },
  ), true)

  // Eligibility bookkeeping + cap.
  assert.equal(privateExec.refinementBudgetRemaining(run.id), 10)
  privateExec.markRefinementEligible(run.id, 'spec-1')
  assert.equal(privateExec.isRefinementEligible(run.id, 'spec-1'), true)
  assert.equal(privateExec.isRefinementEligible(run.id, 'spec-2'), false)

  for (let i = 0; i < 10; i += 1) {
    storage.makeWorker(run, 'verification', asset, `Refine replay ${i}`, 'Bounded refinement.', {
      stepId: `refine:spec-${i}`,
      sourceOrigins: [asset.origin],
      maxTurns: 8,
    })
  }
  assert.equal(privateExec.refinementBudgetRemaining(run.id), 0)
  assert.equal(maxPhase3RefinementJobsForTest(), 10)
})

function maxPhase3RefinementJobsForTest(): number {
  const match = /const maxPhase3RefinementJobs = (\d+)/.exec(executionSource)
  return match ? Number(match[1]) : 0
}

test('M1.5: refinement dispatch is wired from driveVerification and re-checks the run cap', () => {
  const driveBlock = /private driveVerification\(run: Run\) \{[\s\S]{0,12000}?for \(const row of pendingFindings\)/.exec(executionSource)?.[0] ?? ''
  assert.ok(driveBlock, 'driveVerification block not found')
  assert.ok(driveBlock.includes('eligibleRefineSpecIds'))
  assert.ok(driveBlock.includes('this.refinementBudgetRemaining(run.id)'))
  assert.ok(driveBlock.includes('refine:${specId}'))
  assert.ok(/refinement\.dispatched/.test(driveBlock))
  // Inline failures mark eligibility; the normal verification path re-checks it before refining.
  assert.ok(executionSource.includes('this.markRefinementEligible(latestRun.id, updatedSpec.id)'))
  assert.ok(/this\.refinementBudgetRemaining\(current\.id\) > 0/.test(executionSource))
  assert.ok(/if \(strongPreSignal\) this\.markRefinementEligible/.test(executionSource))
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
  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () =>
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
  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () =>
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
