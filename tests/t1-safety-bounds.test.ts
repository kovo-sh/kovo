import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import {
  COMPOSE_PARSER_LIMITS,
  ComposeParseError,
  interpolateComposeString,
  parseComposeDocument,
  parseComposeEnvFile,
  parseYamlSubset,
} from '../src/server/compose-parse.ts'
import {
  ExecReconPlanner,
  resolveSafeVariantSweepFile,
  resolveSafeVariantSweepLocation,
  VARIANT_SWEEP_MAX_FILE_BYTES,
} from '../src/server/exec-recon-planner.ts'
import { Store } from '../src/server/store.ts'
import {
  apexDomainOfHost,
  applyDiscoveredSubdomainsToRun,
  collapseSprawlCandidates,
  discoverSubdomainsForOrigins,
  extractDiscoverableApex,
  isSharedPaasHost,
  isSharedPaasOrigin,
  runDiscoverySubdomainsForRun,
  type DiscoveredSubdomain,
  type SubdomainDiscoveryResult,
  type SubdomainDnsResolver,
} from '../src/server/subdomain-discovery.ts'

function tempDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix))
}

// ============================================================================
// 1. C-2: PSL + Shared-PaaS refusal & zero shared-tenant auto-admission
// ============================================================================

test('C-2: apexDomainOfHost / extractDiscoverableApex refuse shared-PaaS hosts while preserving PSL ccTLD apexes', async () => {
  const sharedPaasHosts = [
    'my-app.vercel.app',
    'sub.my-app.vercel.app',
    'vercel.app',
    'foo.netlify.app',
    'bar.github.io',
    'app.herokuapp.com',
    'site.pages.dev',
    'svc.onrender.com',
    'api.fly.dev',
    'web.railway.app',
    'edge.workers.dev',
    'portal.web.app',
    'portal.firebaseapp.com',
    'contoso.azurewebsites.net',
    'd111111abcdef8.cloudfront.net',
    'bucket.s3.amazonaws.com',
    'svc.amazonaws.com',
    'demo.appspot.com',
    'demo.replit.app',
    'demo.surge.sh',
    'demo.glitch.me',
  ]

  for (const host of sharedPaasHosts) {
    assert.equal(isSharedPaasHost(host), true, `expected ${host} to be classified as shared PaaS`)
    assert.equal(isSharedPaasOrigin(`https://${host}`), true)
    assert.equal(apexDomainOfHost(host), null, `expected shared-PaaS host ${host} to return null apex`)
    assert.equal(extractDiscoverableApex(`https://${host}`), null, `expected https://${host} to be non-discoverable`)
  }

  // Real PSL multi-part ccTLD & standard domains must still resolve accurately
  assert.equal(isSharedPaasHost('baz.co.uk'), false)
  assert.equal(apexDomainOfHost('baz.co.uk'), 'baz.co.uk')
  assert.equal(apexDomainOfHost('sub.baz.co.uk'), 'baz.co.uk')
  assert.equal(apexDomainOfHost('co.uk'), null)
  assert.equal(extractDiscoverableApex('https://baz.co.uk'), 'baz.co.uk')
  assert.equal(extractDiscoverableApex('https://api.baz.co.uk'), 'baz.co.uk')
  assert.equal(apexDomainOfHost('app.example.com'), 'example.com')

  // discoverSubdomainsForOrigins must make ZERO network/DNS calls for shared-PaaS origins
  let fetchCalls = 0
  let dnsCalls = 0
  const stubFetch: typeof fetch = async () => {
    fetchCalls += 1
    return new Response('[]', { status: 200 })
  }
  const stubDns: SubdomainDnsResolver = async () => {
    dnsCalls += 1
    return { cnames: [], addresses: ['76.76.21.21'] }
  }

  const res = await discoverSubdomainsForOrigins(
    ['https://my-app.vercel.app', 'https://foo.netlify.app', 'https://bar.github.io'],
    { fetchImpl: stubFetch, dnsResolver: stubDns },
  )
  assert.equal(fetchCalls, 0)
  assert.equal(dnsCalls, 0)
  assert.deepEqual(res.queriedApexes, [])
  assert.deepEqual(res.discovered, [])
  assert.equal(res.skippedOrigins.length, 3)
})

test('C-2: applyDiscoveredSubdomainsToRun refuses shared-tenant auto-admission even with includeSubdomains=true', async () => {
  const dir = tempDir('kovo-t1-c2-')
  const store = new Store(dir)
  try {
    const proj = store.createProject({
      requestId: randomUUID(),
      name: 'Shared PaaS App',
      seeds: ['https://my-app.vercel.app'],
      environment: 'public',
      includeSubdomains: true,
    })
    const run = store.createRun({
      requestId: randomUUID(),
      projectId: proj.id,
      goal: 'Verify PaaS tenant isolation',
      sourceMode: 'public',
      capabilityTier: 1,
      budgetUsd: 5,
      budgetRequests: 0,
      maxRpsPerOrigin: 3,
      workerConcurrency: 1,
      workerMaxTurns: 10,
    })
    store.command({ requestId: randomUUID(), runId: run.id, action: 'discover', consent: true })
    const reviewRun = store.run(run.id)
    const seedCand = reviewRun.candidates.find(c => c.origin === 'https://my-app.vercel.app')!
    store.command({
      requestId: randomUUID(),
      runId: run.id,
      action: 'scope',
      assetIds: [seedCand.id],
      expectedScopeRevision: reviewRun.scopeRevision,
      consent: true,
      saveProject: false,
      capabilityTier: 1,
      approvalPolicy: 'auto_review',
      approvedPersonaIds: [],
      budgetUsd: 5,
      budgetRequests: 0,
      maxRpsPerOrigin: 3,
    })

    // Even if a synthetic discovery result injects sibling PaaS tenants, none may be admitted
    const synthetic: SubdomainDiscoveryResult = {
      queriedApexes: ['vercel.app'],
      skippedOrigins: [],
      warnings: [],
      wildcardApexes: [],
      discovered: [
        {
          hostname: 'other-tenant.vercel.app',
          origin: 'https://other-tenant.vercel.app',
          parentOrigin: 'https://my-app.vercel.app',
          apexDomain: 'vercel.app',
          cnames: [],
          addresses: ['76.76.21.21'],
          thirdParty: false,
          thirdPartyVendor: null,
          cnameTarget: null,
          sources: ['crt.sh'],
        },
        {
          hostname: 'sibling.my-app.vercel.app',
          origin: 'https://sibling.my-app.vercel.app',
          parentOrigin: 'https://my-app.vercel.app',
          apexDomain: 'my-app.vercel.app',
          cnames: [],
          addresses: ['76.76.21.21'],
          thirdParty: false,
          thirdPartyVendor: null,
          cnameTarget: null,
          sources: ['crt.sh'],
        },
      ],
    }

    const approvedOrigins = new Set(['https://my-app.vercel.app'])
    const applied = applyDiscoveredSubdomainsToRun(store, run.id, synthetic, approvedOrigins)
    assert.deepEqual(applied.admittedOrigins, [])
    assert.deepEqual(applied.candidateOrigins, [])
    assert.deepEqual([...approvedOrigins], ['https://my-app.vercel.app'])

    const afterRun = store.run(run.id)
    assert.equal(afterRun.approved.length, 1)
    assert.equal(
      afterRun.candidates.some(c => c.origin === 'https://other-tenant.vercel.app'),
      false,
      'other-tenant.vercel.app must never be admitted or suggested',
    )

    // Meanwhile, a legitimate ccTLD apex (`baz.co.uk`) with includeSubdomains=true still admits its own subdomain
    const ukProj = store.createProject({
      requestId: randomUUID(),
      name: 'UK Domain App',
      seeds: ['https://baz.co.uk'],
      environment: 'public',
      includeSubdomains: true,
    })
    const ukRun = store.createRun({
      requestId: randomUUID(),
      projectId: ukProj.id,
      goal: 'Verify ccTLD apex behavior',
      sourceMode: 'public',
      capabilityTier: 1,
      budgetUsd: 5,
      budgetRequests: 0,
      maxRpsPerOrigin: 3,
      workerConcurrency: 1,
      workerMaxTurns: 10,
    })
    store.command({ requestId: randomUUID(), runId: ukRun.id, action: 'discover', consent: true })
    const ukReview = store.run(ukRun.id)
    const ukSeed = ukReview.candidates.find(c => c.origin === 'https://baz.co.uk')!
    store.command({
      requestId: randomUUID(),
      runId: ukRun.id,
      action: 'scope',
      assetIds: [ukSeed.id],
      expectedScopeRevision: ukReview.scopeRevision,
      consent: true,
      saveProject: false,
      capabilityTier: 1,
      approvalPolicy: 'auto_review',
      approvedPersonaIds: [],
      budgetUsd: 5,
      budgetRequests: 0,
      maxRpsPerOrigin: 3,
    })

    const ukApproved = new Set(['https://baz.co.uk'])
    const ukApplied = applyDiscoveredSubdomainsToRun(
      store,
      ukRun.id,
      {
        queriedApexes: ['baz.co.uk'],
        skippedOrigins: [],
        warnings: [],
        wildcardApexes: [],
        discovered: [
          {
            hostname: 'api.baz.co.uk',
            origin: 'https://api.baz.co.uk',
            parentOrigin: 'https://baz.co.uk',
            apexDomain: 'baz.co.uk',
            cnames: [],
            addresses: ['93.184.216.34'],
            thirdParty: false,
            thirdPartyVendor: null,
            cnameTarget: null,
            sources: ['crt.sh'],
          },
        ],
      },
      ukApproved,
    )
    assert.deepEqual(ukApplied.admittedOrigins, ['https://api.baz.co.uk'])
    assert.equal(ukApproved.has('https://api.baz.co.uk'), true)
  } finally {
    store.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

// ============================================================================
// 2. H-37: Compose `${VAR}` interpolation never reads host `process.env`
// ============================================================================

test('H-37: compose interpolation never falls back to host process.env while supporting defaults and explicit .env', () => {
  const prevSecret = process.env.SECRET_HOST_ENV
  process.env.SECRET_HOST_ENV = 'sk-host-secret-must-not-leak'
  try {
    const bareVarCompose = [
      'services:',
      '  app:',
      '    image: node:24-bookworm-slim',
      '    environment:',
      '      LEAKED: "${SECRET_HOST_ENV}"',
    ].join('\n')

    // Default (omitted options.env) must NOT read process.env.SECRET_HOST_ENV
    assert.throws(
      () => parseComposeDocument(bareVarCompose),
      /required environment variable "SECRET_HOST_ENV" is not set/,
    )
    assert.throws(
      () => parseYamlSubset('key: "${SECRET_HOST_ENV}"\n'),
      /required environment variable "SECRET_HOST_ENV" is not set/,
    )

    // Even if a caller passes `process.env` directly, compose-parse refuses host env leakage
    assert.throws(
      () => parseComposeDocument(bareVarCompose, { env: process.env }),
      /required environment variable "SECRET_HOST_ENV" is not set/,
    )
    assert.throws(
      () => interpolateComposeString('${SECRET_HOST_ENV}', process.env),
      /required environment variable "SECRET_HOST_ENV" is not set/,
    )

    // `${VAR:-fallback}` resolves to fallback rather than host process.env
    const fallbackCompose = [
      'services:',
      '  app:',
      '    image: node:24-bookworm-slim',
      '    environment:',
      '      API_KEY: "${SECRET_HOST_ENV:-fallback}"',
      '      PORT: "${UNSET_PORT:-8080}"',
    ].join('\n')

    const parsedFallback = parseComposeDocument(fallbackCompose)
    assert.equal(parsedFallback.services[0]?.normalized.environment?.API_KEY, 'fallback')
    assert.equal(parsedFallback.services[0]?.normalized.environment?.PORT, '8080')

    const parsedFallbackWithProcessEnv = parseComposeDocument(fallbackCompose, { env: process.env })
    assert.equal(parsedFallbackWithProcessEnv.services[0]?.normalized.environment?.API_KEY, 'fallback')

    // Explicit `.env` file / env map works as expected
    const dotEnv = parseComposeEnvFile([
      '# Fixture compose .env',
      'APP_TOKEN="explicit-dotenv-token"',
      'PORT=3100',
      'export DB_NAME=fixture_db',
    ].join('\n'))
    const explicitCompose = [
      'services:',
      '  app:',
      '    image: node:24-bookworm-slim',
      '    environment:',
      '      APP_TOKEN: "${APP_TOKEN}"',
      '      PORT: "${PORT:-8080}"',
      '      DB_NAME: "${DB_NAME}"',
      '      HOST_CHECK: "${SECRET_HOST_ENV:-isolated}"',
    ].join('\n')

    const parsedExplicit = parseComposeDocument(explicitCompose, { env: dotEnv })
    assert.deepEqual(parsedExplicit.services[0]?.normalized.environment, {
      APP_TOKEN: 'explicit-dotenv-token',
      PORT: '3100',
      DB_NAME: 'fixture_db',
      HOST_CHECK: 'isolated',
    })
  } finally {
    if (prevSecret === undefined) delete process.env.SECRET_HOST_ENV
    else process.env.SECRET_HOST_ENV = prevSecret
  }
})

// ============================================================================
// 3. H-38: YAML billion-laughs alias bomb rejected cleanly in < 100ms
// ============================================================================

test('H-38: YAML billion-laughs alias bombs (flow, block, merge-key, depth) fail cleanly in < 100ms', () => {
  assert.equal(COMPOSE_PARSER_LIMITS.maxExpandedNodes, 10_000)

  // 1. Classic flow-sequence billion-laughs (10^8 expansion)
  const flowBomb = [
    'x-a: &a ["lol", "lol", "lol", "lol", "lol", "lol", "lol", "lol", "lol", "lol"]',
    'x-b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]',
    'x-c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]',
    'x-d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]',
    'x-e: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d, *d]',
    'x-f: &f [*e, *e, *e, *e, *e, *e, *e, *e, *e, *e]',
    'x-g: &g [*f, *f, *f, *f, *f, *f, *f, *f, *f, *f]',
    'x-h: &h [*g, *g, *g, *g, *g, *g, *g, *g, *g, *g]',
    'services:',
    '  app:',
    '    image: node:24',
  ].join('\n')

  const t0 = performance.now()
  assert.throws(
    () => parseComposeDocument(flowBomb, { env: {} }),
    (err: unknown) => err instanceof ComposeParseError && /budget|nodes|depth/i.test(err.message),
  )
  const elapsedFlowMs = performance.now() - t0
  assert.ok(elapsedFlowMs < 100, `flow alias bomb should fail in <100ms, took ${elapsedFlowMs.toFixed(1)}ms`)

  // 2. Block-mapping exponential alias bomb
  const blockBomb = [
    'x-a: &a',
    '  k1: "x"',
    '  k2: "x"',
    '  k3: "x"',
    '  k4: "x"',
    '  k5: "x"',
    '  k6: "x"',
    '  k7: "x"',
    '  k8: "x"',
    'x-b: &b',
    '  a1: *a',
    '  a2: *a',
    '  a3: *a',
    '  a4: *a',
    '  a5: *a',
    '  a6: *a',
    '  a7: *a',
    '  a8: *a',
    'x-c: &c',
    '  b1: *b',
    '  b2: *b',
    '  b3: *b',
    '  b4: *b',
    '  b5: *b',
    '  b6: *b',
    '  b7: *b',
    '  b8: *b',
    'x-d: &d',
    '  c1: *c',
    '  c2: *c',
    '  c3: *c',
    '  c4: *c',
    '  c5: *c',
    '  c6: *c',
    '  c7: *c',
    '  c8: *c',
    'x-e: &e',
    '  d1: *d',
    '  d2: *d',
    '  d3: *d',
    '  d4: *d',
    '  d5: *d',
    '  d6: *d',
    '  d7: *d',
    '  d8: *d',
    'services:',
    '  app:',
    '    image: node:24',
  ].join('\n')

  const t1 = performance.now()
  assert.throws(
    () => parseComposeDocument(blockBomb, { env: {} }),
    (err: unknown) => err instanceof ComposeParseError && /budget|nodes|depth/i.test(err.message),
  )
  const elapsedBlockMs = performance.now() - t1
  assert.ok(elapsedBlockMs < 100, `block alias bomb should fail in <100ms, took ${elapsedBlockMs.toFixed(1)}ms`)

  // 3. Depth-only alias chain (> 16 levels)
  const depthLines = ['a0: &a0 [1]']
  for (let i = 1; i <= 20; i += 1) {
    depthLines.push(`a${i}: &a${i} [*a${i - 1}]`)
  }
  const t2 = performance.now()
  assert.throws(
    () => parseYamlSubset(depthLines.join('\n'), { env: {} }),
    (err: unknown) => err instanceof ComposeParseError && /depth/i.test(err.message),
  )
  const elapsedDepthMs = performance.now() - t2
  assert.ok(elapsedDepthMs < 100, `alias depth bomb should fail in <100ms, took ${elapsedDepthMs.toFixed(1)}ms`)
})

// ============================================================================
// 4. H-39: Variant sweep path confinement, isFile(), and 256 KiB size cap
// ============================================================================

test('H-39: variant sweep path resolver rejects .. traversal, symlinks outside root, directories, and >256 KiB files', () => {
  const outer = tempDir('kovo-t1-h39-')
  try {
    const reposDir = join(outer, 'repos')
    const demoRepo = join(reposDir, 'demo-app')
    const otherRepo = join(reposDir, 'unmounted-repo')
    const srcDir = join(demoRepo, 'src')
    mkdirSync(srcDir, { recursive: true })
    mkdirSync(otherRepo, { recursive: true })

    const outsideSecret = join(outer, 'outside-secret.txt')
    writeFileSync(outsideSecret, 'db.query(secretToken)\n')
    writeFileSync(join(otherRepo, 'other.ts'), 'db.query(otherToken)\n')

    const validFile = join(srcDir, 'handler.ts')
    writeFileSync(validFile, 'export function run(x: string) { return db.query(x) }\n')

    const hugeFile = join(srcDir, 'huge.ts')
    writeFileSync(hugeFile, 'a'.repeat(VARIANT_SWEEP_MAX_FILE_BYTES + 1))

    // Symlink inside repo escaping to outer file and to /etc/passwd
    const escapeSymlink = join(srcDir, 'escape-link.ts')
    symlinkSync(outsideSecret, escapeSymlink)
    const etcSymlink = join(srcDir, 'etc-passwd-link.ts')
    symlinkSync('/etc/passwd', etcSymlink)

    // 1. Valid in-repo file succeeds
    const ok = resolveSafeVariantSweepLocation(reposDir, 'demo-app', 'src/handler.ts', ['/repos/demo-app'])
    assert.ok(ok, 'legitimate in-repo file must be accepted')
    assert.equal(ok.realPath.endsWith('/demo-app/src/handler.ts'), true)

    // 2. Relative `..` escapes rejected
    assert.equal(
      resolveSafeVariantSweepLocation(reposDir, 'demo-app', '../../etc/passwd', ['/repos/demo-app']),
      null,
      '../../etc/passwd traversal must be rejected',
    )
    assert.equal(
      resolveSafeVariantSweepLocation(reposDir, 'demo-app', '../../outside-secret.txt', ['/repos/demo-app']),
      null,
      'parent-dir escape must be rejected',
    )
    assert.equal(
      resolveSafeVariantSweepLocation(reposDir, '../../etc', 'passwd', ['/repos/demo-app']),
      null,
      'repo traversal must be rejected',
    )
    assert.equal(
      resolveSafeVariantSweepLocation(reposDir, 'demo-app', '/etc/passwd', ['/repos/demo-app']),
      null,
      'absolute path must be rejected',
    )

    // 3. Symlink escapes outside repo root rejected via canonical realpath
    assert.equal(
      resolveSafeVariantSweepLocation(reposDir, 'demo-app', 'src/escape-link.ts', ['/repos/demo-app']),
      null,
      'symlink escaping to outer file must be rejected',
    )
    assert.equal(
      resolveSafeVariantSweepLocation(reposDir, 'demo-app', 'src/etc-passwd-link.ts', ['/repos/demo-app']),
      null,
      'symlink escaping to /etc/passwd must be rejected',
    )
    assert.equal(
      resolveSafeVariantSweepFile(demoRepo, escapeSymlink),
      null,
      'resolveSafeVariantSweepFile must reject symlink outside root',
    )

    // 4. Unmounted sibling repo rejected
    assert.equal(
      resolveSafeVariantSweepLocation(reposDir, 'unmounted-repo', 'other.ts', ['/repos/demo-app']),
      null,
      'unmounted repo must be rejected when mountedRepos list is enforced',
    )

    // 5. Directory rejected (stat.isFile() required)
    assert.equal(
      resolveSafeVariantSweepLocation(reposDir, 'demo-app', 'src', ['/repos/demo-app']),
      null,
      'directory path must be rejected',
    )

    // 6. Oversized file (> 256 KiB) rejected
    assert.equal(
      resolveSafeVariantSweepLocation(reposDir, 'demo-app', 'src/huge.ts', ['/repos/demo-app']),
      null,
      'file exceeding 256 KiB cap must be rejected',
    )
  } finally {
    rmSync(outer, { recursive: true, force: true })
  }
})

test('H-39: runPostConfirmationVariantSweep ignores path-traversal & symlink-escape codeLocations and never reads outside repo root', async () => {
  const outer = tempDir('kovo-t1-h39-e2e-')
  const storeDir = join(outer, 'store')
  const reposDir = join(outer, 'repos')
  const demoRepo = join(reposDir, 'demo-app')
  const srcDir = join(demoRepo, 'src')
  mkdirSync(storeDir, { recursive: true })
  mkdirSync(srcDir, { recursive: true })

  const store = new Store(storeDir)
  try {
    // Secret file outside repo containing a call signature that also exists in sibling.ts
    const outsideSecret = join(outer, 'outside-secret.ts')
    writeFileSync(outsideSecret, 'export const leaked = secretVault.readAll(token)\n')
    writeFileSync(join(srcDir, 'sibling.ts'), 'export const s = secretVault.readAll(token)\n')
    symlinkSync(outsideSecret, join(srcDir, 'symlink-escape.ts'))

    const prevAllowLab = process.env.KOVO_ALLOW_LOCAL_LAB
    process.env.KOVO_ALLOW_LOCAL_LAB = '1'
    let runId: string
    try {
      const proj = store.createProject({
        requestId: randomUUID(),
        name: 'Variant Sweep Safety',
        seeds: ['http://127.0.0.1:4199'],
        environment: 'local-lab',
      })
      const created = store.createRun({
        requestId: randomUUID(),
        projectId: proj.id,
        goal: 'Verify variant sweep confinement',
        sourceMode: 'public',
        capabilityTier: 1,
        budgetUsd: 5,
        budgetRequests: 0,
        maxRpsPerOrigin: 3,
        workerConcurrency: 1,
        workerMaxTurns: 10,
      })
      runId = created.id
      store.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
      const reviewRun = store.run(runId)
      const seedCand = reviewRun.candidates[0]!
      store.command({
        requestId: randomUUID(),
        runId,
        action: 'scope',
        assetIds: [seedCand.id],
        expectedScopeRevision: reviewRun.scopeRevision,
        consent: true,
        saveProject: false,
        capabilityTier: 1,
        approvalPolicy: 'auto_review',
        approvedPersonaIds: [],
        budgetUsd: 5,
        budgetRequests: 0,
        maxRpsPerOrigin: 3,
      })
    } finally {
      if (prevAllowLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
      else process.env.KOVO_ALLOW_LOCAL_LAB = prevAllowLab
    }

    const run = store.run(runId)
    const planner = new ExecReconPlanner({
      storage: store,
      broker: {} as never,
      backend: {} as never,
      approvedOriginsSet: (r: typeof run) => new Set(r.candidates.filter(c => r.approved.includes(c.id)).map(c => c.origin)),
    } as never)

    // Case A: traversal path `../../outside-secret.ts` — must NOT read outsideSecret and therefore must NOT discover sibling.ts
    await planner.runPostConfirmationVariantSweep(
      run,
      {
        id: 'finding-traversal',
        runId,
        replaySpecId: null,
        finding: {
          title: 'Traversal test finding',
          origin: 'http://127.0.0.1:4199',
          category: 'broken-access-control',
          codeLocations: [{ repo: 'demo-app', file: '../../outside-secret.ts', startLine: 1, endLine: 1 }],
        },
      } as never,
      reposDir,
      ['/repos/demo-app'],
    )
    assert.equal(
      store.listChainSteps(runId, run.goalRevision).length,
      0,
      'traversal path must never be read to seed variant sweep steps',
    )

    // Case B: symlink escape `src/symlink-escape.ts` — must NOT read outsideSecret
    await planner.runPostConfirmationVariantSweep(
      run,
      {
        id: 'finding-symlink',
        runId,
        replaySpecId: null,
        finding: {
          title: 'Symlink escape test finding',
          origin: 'http://127.0.0.1:4199',
          category: 'broken-access-control',
          codeLocations: [{ repo: 'demo-app', file: 'src/symlink-escape.ts', startLine: 1, endLine: 1 }],
        },
      } as never,
      reposDir,
      ['/repos/demo-app'],
    )
    assert.equal(
      store.listChainSteps(runId, run.goalRevision).length,
      0,
      'symlink pointing outside repo root must never be read',
    )

    // Case C: legitimate in-repo file DOES read call signature and finds in-repo sibling (while skipping symlink-escape.ts)
    writeFileSync(join(srcDir, 'primary.ts'), 'export const p = secretVault.readAll(token)\n')
    await planner.runPostConfirmationVariantSweep(
      run,
      {
        id: 'finding-legit',
        runId,
        replaySpecId: null,
        finding: {
          title: 'Legit in-repo finding',
          origin: 'http://127.0.0.1:4199',
          category: 'broken-access-control',
          codeLocations: [{ repo: 'demo-app', file: 'src/primary.ts', startLine: 1, endLine: 1 }],
        },
      } as never,
      reposDir,
      ['/repos/demo-app'],
    )
    const steps = store.listChainSteps(runId, run.goalRevision)
    assert.equal(steps.length, 1, 'legitimate in-repo finding should discover exactly 1 in-repo sibling (and skip symlink)')
    assert.ok(steps[0]!.title.includes('src/sibling.ts'))
  } finally {
    store.close()
    rmSync(outer, { recursive: true, force: true })
  }
})

// ============================================================================
// 5. #621: crt.sh query params, incremental per-source streaming, sprawl collapse
// ============================================================================

test('#621: crt.sh uses exclude=expired&deduplicate=Y, onBatch streams incrementally before slow sources finish, and sprawl patterns collapse', async () => {
  // 1. Sprawl collapsing unit check
  const noisy = [
    'api.sprawl.example',
    'app.sprawl.example',
    'auth.sprawl.example',
    'admin.sprawl.example',
    'billing.sprawl.example',
    'oauth.sprawl.example',
    'www.sprawl.example',
    ...Array.from({ length: 50 }, (_, i) => `pr-${i + 1}.sprawl.example`),
    ...Array.from({ length: 40 }, (_, i) => `deploy-preview-${i + 1}.sprawl.example`),
    ...Array.from({ length: 30 }, (_, i) => `preview-${i + 1}.sprawl.example`),
    ...Array.from({ length: 40 }, (_, i) => `shard-${100 + i}.sprawl.example`),
  ]
  const collapsed = collapseSprawlCandidates(noisy, 'sprawl.example')
  for (const hi of ['api', 'app', 'auth', 'admin', 'billing', 'oauth', 'www']) {
    assert.ok(collapsed.includes(`${hi}.sprawl.example`), `high-signal host ${hi} must be preserved`)
  }
  assert.equal(collapsed.filter(h => /^pr-\d+\./.test(h)).length, 1, 'pr-* sprawl must collapse to 1 representative')
  assert.equal(collapsed.filter(h => /^deploy-preview-\d+\./.test(h)).length, 1, 'deploy-preview-* must collapse to 1')
  assert.equal(collapsed.filter(h => /^preview-\d+\./.test(h)).length, 1, 'preview-* must collapse to 1')
  assert.equal(collapsed.filter(h => /^shard-\d{3,}\./.test(h)).length, 1, 'shard-NNN must collapse to 1')

  // 2. Incremental per-source streaming + crt.sh URL params
  let crtUrlSeen = ''
  let releaseCrt!: () => void
  const crtGate = new Promise<void>(resolve => { releaseCrt = resolve })

  const streamingFetch: typeof fetch = async input => {
    const url = String(input)
    if (url.includes('crt.sh')) {
      crtUrlSeen = url
      await crtGate
      const entries = [
        ...Array.from({ length: 25 }, (_, i) => ({ name_value: `pr-${i + 1}.stream.example` })),
        { name_value: 'billing.stream.example\noauth.stream.example' },
      ]
      return new Response(JSON.stringify(entries), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    if (url.includes('certspotter')) {
      return new Response(JSON.stringify([{ dns_names: ['cs-fast.stream.example'] }]), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }
    if (url.includes('hackertarget')) {
      return new Response('ht-fast.stream.example,93.184.216.10\n', { status: 200 })
    }
    return new Response('', { status: 404 })
  }

  const streamingDns: SubdomainDnsResolver = async host => {
    if (host.startsWith('kovo-nx-')) return { cnames: [], addresses: [] }
    if (
      host === 'api.stream.example' ||
      host === 'cs-fast.stream.example' ||
      host === 'ht-fast.stream.example' ||
      host === 'billing.stream.example' ||
      host === 'oauth.stream.example' ||
      /^pr-\d+\.stream\.example$/.test(host)
    ) {
      return { cnames: [], addresses: ['93.184.216.34'] }
    }
    return { cnames: [], addresses: [] }
  }

  const dir = tempDir('kovo-t1-stream-')
  const store = new Store(dir)
  try {
    const proj = store.createProject({
      requestId: randomUUID(),
      name: 'Stream App',
      seeds: ['https://stream.example'],
      environment: 'public',
    })
    const run = store.createRun({
      requestId: randomUUID(),
      projectId: proj.id,
      goal: 'Verify streaming discovery',
      sourceMode: 'public',
      capabilityTier: 1,
      budgetUsd: 5,
      budgetRequests: 0,
      maxRpsPerOrigin: 3,
      workerConcurrency: 1,
      workerMaxTurns: 10,
    })
    store.command({ requestId: randomUUID(), runId: run.id, action: 'discover', consent: true })

    const batches: DiscoveredSubdomain[][] = []
    let sawFastSourcesBeforeCrt = false
    let persistedBeforeCrt = 0

    const discoveryPromise = runDiscoverySubdomainsForRun(store, run.id, {
      fetchImpl: streamingFetch,
      dnsResolver: streamingDns,
      retryDelayMs: 0,
      onBatch: batch => {
        batches.push(batch)
        const allSoFar = batches.flat().map(b => b.origin)
        if (
          allSoFar.includes('https://api.stream.example') &&
          allSoFar.includes('https://cs-fast.stream.example') &&
          allSoFar.includes('https://ht-fast.stream.example') &&
          !sawFastSourcesBeforeCrt
        ) {
          sawFastSourcesBeforeCrt = true
          persistedBeforeCrt = store.run(run.id).candidates.length
          releaseCrt()
        }
      },
    })

    // Safety fallback timer in case anything unexpectedly hung
    const safety = setTimeout(() => releaseCrt(), 2_000)
    safety.unref?.()
    const res = await discoveryPromise
    clearTimeout(safety)

    assert.equal(sawFastSourcesBeforeCrt, true, 'fast sources (dns_sweep, certspotter, hackertarget) must stream via onBatch BEFORE slow crt.sh completes')
    assert.ok(persistedBeforeCrt >= 4, `expected seed + fast sources persisted before crt.sh finished, got ${persistedBeforeCrt}`)
    assert.ok(crtUrlSeen.includes('exclude=expired'), `crt.sh URL must include exclude=expired: ${crtUrlSeen}`)
    assert.ok(crtUrlSeen.includes('deduplicate=Y'), `crt.sh URL must include deduplicate=Y: ${crtUrlSeen}`)

    // Verify crt.sh sprawl (25 pr-* hosts) collapsed to 1 while billing & oauth were preserved
    const origins = res.discovery.discovered.map(d => d.origin)
    assert.ok(origins.includes('https://billing.stream.example'))
    assert.ok(origins.includes('https://oauth.stream.example'))
    assert.equal(origins.filter(o => /^https:\/\/pr-\d+\./.test(o)).length, 1, 'pr-* CT sprawl must collapse to 1')
  } finally {
    store.close()
    rmSync(dir, { recursive: true, force: true })
  }
})
