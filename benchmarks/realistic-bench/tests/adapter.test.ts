// Adapter self-tests: run against an injected fake engine + fake materialized app.
// Asserts the findings schema, dedupe/telemetry, and that ground truth is never read.
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import assert from 'node:assert/strict'
import { runKovoAgainstMaterialized, readMaterializedSurface, vulnClassForFinding } from '../kovo-adapter.ts'
import type {
  EngineEnvLike, EngineHandleLike, EngineModuleLike, HypothesisLike, MaterializedAppLike,
  ProfileCapsLike, SynthesizedSpecLike,
} from '../kovo-adapter.ts'
import { validateFindings } from '../grader/schema.ts'

function fixtureTree(app = 'acme-saas', routes: Record<string, { method: string; path: string }> = {}): string {
  const root = mkdtempSync(join(tmpdir(), 'rb-adapter-test-'))
  const src = join(root, 'apps', app, 'src')
  mkdirSync(src, { recursive: true })
  writeFileSync(join(src, 'variant.json'), JSON.stringify({
    app,
    apiPrefix: '/api',
    idFormat: 'int',
    routes: {
      login: { method: 'POST', path: '/api/auth/login' },
      getProject: { method: 'GET', path: '/api/projects/:projectId' },
      search: { method: 'GET', path: '/api/search' },
      ...routes,
    },
    params: { projectId: 'projectId', query: 'q' },
  }))
  return src
}

function fixtureStarted(sourceDir: string, origin = 'http://127.0.0.1:49152'): { app: MaterializedAppLike; reads: () => number } {
  let truthReads = 0
  const plan = {
    seed: 42,
    routes: { login: { method: 'POST', path: '/api/auth/login' } },
    params: {},
    personas: {
      persona_a: { id: 'persona_a', email: 'a@example.test', password: 'pw-a', tenant: 'acme', role: 'owner' },
      persona_b: { id: 'persona_b', email: 'b@example.test', password: 'pw-b', tenant: 'globex', role: 'member' },
    },
  }
  Object.defineProperty(plan, 'sites', {
    get() { truthReads += 1; throw new Error('adapter must not read plan.sites') },
  })
  const started = {
    app: 'acme-saas',
    origin,
    sourceDir,
    plan,
    stop: async () => undefined,
  }
  Object.defineProperty(started, 'groundTruth', {
    get() { truthReads += 1; throw new Error('adapter must not read groundTruth') },
  })
  return { app: started as unknown as MaterializedAppLike, reads: () => truthReads }
}

const loginFetch = (async () => new Response('{"ok":true}', {
  status: 200,
  headers: { 'content-type': 'application/json', 'set-cookie': 'sid=session-abc; Path=/; HttpOnly' },
})) as unknown as typeof fetch

function fakeEngine(overrides: Partial<EngineModuleLike> = {}): {
  engine: EngineModuleLike
  seen: { handle: EngineHandleLike | null; cleaned: number; verified: number }
} {
  const seen = { handle: null as EngineHandleLike | null, cleaned: 0, verified: 0 }
  const endpoint = {
    method: 'GET', path: '/api/projects/:projectId', source: 'fake-recon',
    params: [{ name: 'projectId', location: 'path', isObjectId: true, isCsrf: false }],
  }
  const searchEndpoint = {
    method: 'GET', path: '/api/search', source: 'fake-recon',
    params: [{ name: 'q', location: 'query', isObjectId: false, isCsrf: false }],
  }
  const hypotheses: HypothesisLike[] = [
    { key: 'h1', endpoint, probeClass: 'authz_matrix', param: endpoint.params[0], location: 'path', method: 'GET' },
    { key: 'h2', endpoint: searchEndpoint, probeClass: 'sqli_boolean', param: searchEndpoint.params[0], location: 'query', method: 'GET' },
  ]
  const caps: ProfileCapsLike = { mode: 'v4-full', tier: 3, inlineRetries: 0 }
  const env = {
    probeEnv: { origin: 'http://127.0.0.1:49152', slowProbesLeft: 0 },
    requestsUsed: () => 0,
    cleanup: async () => { seen.cleaned += 1 },
  } as unknown as EngineEnvLike
  const base: EngineModuleLike = {
    profileCaps: () => caps,
    createEngineEnv: async (handle) => { seen.handle = handle; return env },
    discoverEndpoints: async () => [endpoint, searchEndpoint],
    formHypotheses: () => ({ hypotheses, encodingSkips: [] }),
    runHypothesis: async (hyp) => ({
      hyp, verdict: 'signal', anomalies: [], csrfRejected: false, contextReset: false, tierBlocked: false,
    }),
    synthesizeSpec: (outcome): SynthesizedSpecLike | null => outcome.hyp.probeClass === 'sqli_boolean'
      ? { kind: 'sql_boolean_diff', spec: { title: 'Boolean-based SQL injection differential', cwe: 'CWE-89', category: 'injection-input', severity: 'high' } }
      : { kind: 'http_chain', spec: { title: 'Cross-actor object access', cwe: 'CWE-639', category: 'broken-access-control', severity: 'high' } },
    selectVerifierBackend: async () => ({ kind: 'local-jq', backend: {} }),
    verifyReplaySpec: async () => { seen.verified += 1; return { verdict: 'confirmed' } },
  }
  return { engine: { ...base, ...overrides }, seen }
}

test('adapter emits grader-schema findings from materialized routes without touching truth', async () => {
  const prev = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  const src = fixtureTree()
  const { app: started, reads } = fixtureStarted(src)
  const { engine, seen } = fakeEngine()
  let ticks = 5000
  try {
    const result = await runKovoAgainstMaterialized({
      treeDir: src, seed: 42, app: 'acme-saas', profileMode: 'v4-full', verifierBackend: 'local-jq',
    }, {
      startApp: async () => started,
      loadEngine: async () => engine,
      fetchImpl: loginFetch,
      now: () => (ticks += 10),
    })

    const valid = validateFindings(result.findings)
    assert.equal(valid.ok, true, valid.errors.join('\n'))
    assert.equal(result.findings.length, 2)
    assert.deepEqual(result.findings.map(f => f.vulnClass).sort(), ['idor', 'sqli'])
    for (const f of result.findings) {
      assert.equal(f.status, 'runtime_confirmed')
      assert.equal(typeof f.submittedAtMs, 'number')
      assert.equal(f.endpoints.length, 1)
      assert.ok(f.endpoints[0]!.path.startsWith('/'))
    }
    const idor = result.findings.find(f => f.vulnClass === 'idor')!
    assert.equal(idor.endpoints[0]!.path, '/api/projects/:projectId')
    assert.deepEqual(idor.params, ['projectId'])

    // Login used the materialized route and handed a cookie persona to the engine.
    assert.equal(seen.handle?.personas.persona_a?.cookie, 'sid=session-abc')
    assert.equal(seen.cleaned, 1)
    assert.equal(seen.verified, 2)
    assert.equal(result.telemetry.hypotheses?.length, 2)
    assert.equal(result.telemetry.totalCostUsd, 0)
    // 2 recon endpoints + the login route merged from variant.json.
    assert.equal(result.endpointsDiscovered, 3)
    assert.equal(result.signalsObserved, 2)

    // Truth discipline: neither groundTruth nor plan.sites was ever read.
    assert.equal(reads(), 0)
    const blob = JSON.stringify({ findings: result.findings, telemetry: result.telemetry })
    assert.doesNotMatch(blob, /decoy|hardened|vulnerable/i)
  } finally {
    await new Promise<void>(r => setImmediate(r))
    rmSync(join(src, '..', '..', '..'), { recursive: true, force: true })
    if (prev === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prev
  }
})

test('adapter dedupes repeated confirmed signals on the same endpoint/param/class', async () => {
  const prev = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  const src = fixtureTree()
  const { app: started } = fixtureStarted(src)
  const endpoint = {
    method: 'GET', path: '/api/projects/:projectId', source: 'fake-recon',
    params: [{ name: 'projectId', location: 'path', isObjectId: true, isCsrf: false }],
  }
  const dup = fakeEngine({
    formHypotheses: () => ({
      hypotheses: [
        { key: 'a', endpoint, probeClass: 'authz_matrix', param: endpoint.params[0], location: 'path', method: 'GET' },
        { key: 'b', endpoint, probeClass: 'authz_matrix', param: endpoint.params[0], location: 'path', method: 'GET' },
      ], encodingSkips: [],
    }),
  })
  try {
    const result = await runKovoAgainstMaterialized({
      treeDir: src, seed: 42, app: 'acme-saas', profileMode: 'v4-full', verifierBackend: 'local-jq',
    }, { startApp: async () => started, loadEngine: async () => dup.engine, fetchImpl: loginFetch })
    assert.equal(result.findings.length, 1)
    assert.equal(result.duplicateSignals, 1)
    assert.equal(result.signalsObserved, 2)
  } finally {
    rmSync(join(src, '..', '..', '..'), { recursive: true, force: true })
    if (prev === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prev
  }
})

test('adapter refuses to run unless the local lab is explicitly allowed', async () => {
  const prev = process.env.KOVO_ALLOW_LOCAL_LAB
  delete process.env.KOVO_ALLOW_LOCAL_LAB
  const src = fixtureTree()
  let startedCalled = false
  try {
    await assert.rejects(
      runKovoAgainstMaterialized({
        treeDir: src, seed: 1, app: 'acme-saas', profileMode: 'v4-full', verifierBackend: 'local-jq',
      }, { startApp: async () => { startedCalled = true; return fixtureStarted(src).app } }),
      /KOVO_ALLOW_LOCAL_LAB/,
    )
    assert.equal(startedCalled, false)
  } finally {
    rmSync(join(src, '..', '..', '..'), { recursive: true, force: true })
    if (prev !== undefined) process.env.KOVO_ALLOW_LOCAL_LAB = prev
  }
})

test('adapter rejects a treeDir that is not the started app sourceDir', async () => {
  const prev = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  const src = fixtureTree()
  const other = fixtureTree()
  const { app: started } = fixtureStarted(other)
  try {
    await assert.rejects(
      runKovoAgainstMaterialized({
        treeDir: src, seed: 1, app: 'acme-saas', profileMode: 'v4-full', verifierBackend: 'local-jq',
      }, { startApp: async () => started, loadEngine: async () => fakeEngine().engine, fetchImpl: loginFetch }),
      /refusing to probe a different tree/,
    )
  } finally {
    rmSync(join(src, '..', '..', '..'), { recursive: true, force: true })
    rmSync(join(other, '..', '..', '..'), { recursive: true, force: true })
    if (prev === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prev
  }
})

test('readMaterializedSurface derives routes/params from variant.json only', () => {
  const src = fixtureTree()
  try {
    const surface = readMaterializedSurface(src)
    assert.equal(surface.app, 'acme-saas')
    assert.equal(surface.apiPrefix, '/api')
    const project = surface.routes.find(r => r.routeKey === 'getProject')!
    assert.deepEqual(project.params, ['projectId'])
    assert.equal(project.method, 'GET')
  } finally {
    rmSync(join(src, '..', '..', '..'), { recursive: true, force: true })
  }
})

test('vulnClassForFinding maps every engine CWE family it can emit', () => {
  const cases: Array<[string, string | undefined, string | undefined]> = [
    ['CWE-89', 'injection-input', 'sqli'],
    ['CWE-639', 'broken-access-control', 'idor'],
    ['CWE-915', 'mass-assignment', 'mass_assignment'],
    ['CWE-918', undefined, 'ssrf'],
    ['CWE-611', undefined, 'xxe'],
    ['CWE-1336', undefined, 'ssti'],
    ['CWE-352', undefined, 'csrf'],
    ['CWE-601', undefined, 'open_redirect'],
    ['CWE-524', undefined, 'cache_poisoning'],
    ['CWE-345', undefined, 'jwt'],
    ['CWE-9999', undefined, undefined],
  ]
  for (const [cwe, category, expected] of cases) {
    assert.equal(vulnClassForFinding(cwe, category), expected, `${cwe}/${category}`)
  }
})
