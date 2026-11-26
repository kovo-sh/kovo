import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import {
  collectVariantSweepSiblingHits,
  isSensitiveRepoEntry,
  isSensitiveRepoRelativePath,
  resolveSafeVariantSweepFile,
  resolveSafeVariantSweepLocation,
} from '../src/server/exec-recon-planner.ts'
import { Store } from '../src/server/store.ts'
import { canonicalPathAndQuery, hasUnsafeAdmissionPath } from '../src/server/scope-policy.ts'
import {
  applyDiscoveredSubdomainsToRun,
  autoAdmitAnchorForOrigin,
  discoverSubdomainsForOrigins,
  isMultiTenantSaasHost,
  matchesAutoAdmitAnchor,
  type SubdomainDiscoveryResult,
  type SubdomainDnsResolver,
} from '../src/server/subdomain-discovery.ts'

function tempDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix))
}

test('R2-H-5: autoAdmitAnchorForOrigin strips leading www., refuses PaaS/SaaS, and admits strictly *.anchor', () => {
  assert.equal(autoAdmitAnchorForOrigin('https://www.corp.example'), 'corp.example')
  assert.equal(autoAdmitAnchorForOrigin('https://corp.example'), 'corp.example')
  assert.equal(autoAdmitAnchorForOrigin('https://app.corp.example'), 'app.corp.example')
  assert.equal(autoAdmitAnchorForOrigin('https://www.app.corp.example'), 'app.corp.example')
  assert.equal(autoAdmitAnchorForOrigin('https://tenant.unlisted-saas.io'), 'tenant.unlisted-saas.io')

  // Multi-tenant PaaS, SaaS, bare suffixes, local, and IP hosts never produce an anchor
  for (const blocked of [
    'https://my-app.vercel.app',
    'https://www.vercel.app',
    'https://tenant.zendesk.com',
    'https://tenant.atlassian.net',
    'https://docs.gitbook.io',
    'https://co.uk',
    'https://127.0.0.1:8080',
    'https://localhost:3000',
  ]) {
    assert.equal(autoAdmitAnchorForOrigin(blocked), null, `expected ${blocked} to refuse auto-admit anchor`)
  }
  assert.equal(isMultiTenantSaasHost('acme.zendesk.com'), true)
  assert.equal(isMultiTenantSaasHost('acme.example'), false)

  // Strict *.anchor matching
  assert.equal(matchesAutoAdmitAnchor('x.app.corp.example', 'app.corp.example'), true)
  assert.equal(matchesAutoAdmitAnchor('api.corp.example', 'app.corp.example'), false)
  assert.equal(matchesAutoAdmitAnchor('other-tenant.unlisted-saas.io', 'tenant.unlisted-saas.io'), false)
  assert.equal(matchesAutoAdmitAnchor('sub.tenant.unlisted-saas.io', 'tenant.unlisted-saas.io'), true)
})

test('R2-H-5: discoverSubdomainsForOrigins checks seed third-party CNAMEs and applyDiscoveredSubdomainsToRun refuses wildcard-only DNS hosts', async t => {
  const dir = tempDir('kovo-r2h5-seed-')
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const store = new Store(dir)
  t.after(() => store.close())

  // 1. Subdomain seed pointing to a third-party SaaS CNAME must be skipped
  const stubFetch: typeof fetch = async () => new Response('[]', { status: 200 })
  const stubDns: SubdomainDnsResolver = async host => {
    if (host === 'help.corp.example') {
      return { cnames: ['corp.obscure-helpdesk.io'], addresses: ['198.51.100.10'] }
    }
    return { cnames: [], addresses: [] }
  }
  const seedRes = await discoverSubdomainsForOrigins(['https://help.corp.example'], {
    fetchImpl: stubFetch,
    dnsResolver: stubDns,
  })
  assert.deepEqual(seedRes.queriedApexes, [])
  assert.deepEqual(seedRes.skippedOrigins, ['https://help.corp.example'])
  assert.deepEqual(seedRes.discovered, [])

  // 2. Wildcard-only DNS hosts stay unapproved candidates even when includeSubdomains=true
  const proj = store.createProject({
    requestId: randomUUID(),
    name: 'Wildcard Guard Project',
    seeds: ['https://wild.example'],
    environment: 'public',
    includeSubdomains: true,
  })
  const run = store.createRun({
    requestId: randomUUID(),
    projectId: proj.id,
    goal: 'Test wildcard auto-admit refusal',
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
  const seedCand = reviewRun.candidates[0]!
  store.command({
    requestId: randomUUID(),
    runId: run.id,
    action: 'scope',
    assetIds: [seedCand.id],
    expectedScopeRevision: reviewRun.scopeRevision,
    consent: true,
    capabilityTier: 1,
  })

  const wildDiscovery: SubdomainDiscoveryResult = {
    queriedApexes: ['wild.example'],
    skippedOrigins: [],
    warnings: [],
    wildcardApexes: ['wild.example'],
    discovered: [
      {
        hostname: 'ghost.wild.example',
        origin: 'https://ghost.wild.example',
        parentOrigin: 'https://wild.example',
        apexDomain: 'wild.example',
        cnames: [],
        addresses: ['203.0.113.42'],
        thirdParty: false,
        thirdPartyVendor: null,
        cnameTarget: null,
        wildcardOnly: true,
        sources: ['crt.sh'],
      },
    ],
  }
  const approvedOrigins = new Set(['https://wild.example'])
  const applied = applyDiscoveredSubdomainsToRun(store, run.id, wildDiscovery, approvedOrigins)
  assert.deepEqual(applied.admittedOrigins, [])
  assert.deepEqual(applied.candidateOrigins, ['https://ghost.wild.example'])
  assert.equal(approvedOrigins.has('https://ghost.wild.example'), false)
  assert.equal(store.run(run.id).approved.length, 1)
})

test('R2-H-5: setScope persists operator-declined hosts, blocks re-admission, and admitDynamicOrigin bumps scopeRevision + emits event', () => {
  const dir = tempDir('kovo-r2h5-declined-')
  try {
    let store = new Store(dir)
    const proj = store.createProject({
      requestId: randomUUID(),
      name: 'Anchored Scope Project',
      seeds: ['https://app.corp.example'],
      environment: 'public',
      includeSubdomains: true,
    })
    const created = store.createRun({
      requestId: randomUUID(),
      projectId: proj.id,
      goal: 'Verify anchored auto-admit and declined set',
      sourceMode: 'public',
      capabilityTier: 1,
      budgetUsd: 5,
      budgetRequests: 0,
      maxRpsPerOrigin: 3,
      workerConcurrency: 1,
      workerMaxTurns: 10,
    })

    // Pre-review discovery surfaces sibling and declined hosts
    store.command({ requestId: randomUUID(), runId: created.id, action: 'discover', consent: true })
    store.suggestCandidateHost(store.run(created.id), 'https://api.corp.example', 'subdomain_discovery', false)
    store.suggestCandidateHost(store.run(created.id), 'https://admin.app.corp.example', 'subdomain_discovery', false)

    const reviewRun = store.run(created.id)
    const appSeed = reviewRun.candidates.find(c => c.origin === 'https://app.corp.example')!
    const apiCand = reviewRun.candidates.find(c => c.origin === 'https://api.corp.example')!
    const adminCand = reviewRun.candidates.find(c => c.origin === 'https://admin.app.corp.example')!

    // Operator approves ONLY app.corp.example and explicitly declines api.corp.example and admin.app.corp.example
    store.command({
      requestId: randomUUID(),
      runId: created.id,
      action: 'scope',
      assetIds: [appSeed.id],
      expectedScopeRevision: reviewRun.scopeRevision,
      consent: true,
      capabilityTier: 1,
    })
    const revAfterScope = store.run(created.id).scopeRevision
    assert.equal(revAfterScope, 1)

    // Reopen Store to verify declined_origins persists on disk across restarts
    store.close()
    store = new Store(dir)
    assert.deepEqual(
      store.runsRepo.getDeclinedOrigins(created.id).sort(),
      ['https://admin.app.corp.example', 'https://api.corp.example'],
    )

    // Direct admitDynamicOrigin refuses operator-declined host without bumping scopeRevision
    const directRefused = store.runsRepo.admitDynamicOrigin({
      runId: created.id,
      origin: 'https://admin.app.corp.example',
      source: 'lab_runner',
    })
    assert.equal(directRefused.admitted, false)
    assert.equal(directRefused.reason, 'declined_by_operator')
    assert.equal(store.run(created.id).scopeRevision, revAfterScope)

    // Phase-0 discovery finds:
    //  - api.corp.example (declined + outside *.app.corp.example) -> MUST NOT admit
    //  - admin.app.corp.example (under *.app.corp.example, BUT operator-declined!) -> MUST NOT admit
    //  - other.corp.example (outside *.app.corp.example) -> MUST NOT admit (stays candidate-only)
    //  - x.app.corp.example (new, under *.app.corp.example, not declined) -> MUST admit + bump scopeRevision + emit event
    const discovery: SubdomainDiscoveryResult = {
      queriedApexes: ['corp.example'],
      skippedOrigins: [],
      warnings: [],
      wildcardApexes: [],
      discovered: [
        {
          hostname: 'api.corp.example',
          origin: 'https://api.corp.example',
          parentOrigin: 'https://app.corp.example',
          apexDomain: 'corp.example',
          cnames: [],
          addresses: ['93.184.216.34'],
          thirdParty: false,
          thirdPartyVendor: null,
          cnameTarget: null,
          sources: ['crt.sh'],
        },
        {
          hostname: 'admin.app.corp.example',
          origin: 'https://admin.app.corp.example',
          parentOrigin: 'https://app.corp.example',
          apexDomain: 'corp.example',
          cnames: [],
          addresses: ['93.184.216.34'],
          thirdParty: false,
          thirdPartyVendor: null,
          cnameTarget: null,
          sources: ['crt.sh'],
        },
        {
          hostname: 'other.corp.example',
          origin: 'https://other.corp.example',
          parentOrigin: 'https://app.corp.example',
          apexDomain: 'corp.example',
          cnames: [],
          addresses: ['93.184.216.34'],
          thirdParty: false,
          thirdPartyVendor: null,
          cnameTarget: null,
          sources: ['crt.sh'],
        },
        {
          hostname: 'x.app.corp.example',
          origin: 'https://x.app.corp.example',
          parentOrigin: 'https://app.corp.example',
          apexDomain: 'corp.example',
          cnames: [],
          addresses: ['93.184.216.34'],
          thirdParty: false,
          thirdPartyVendor: null,
          cnameTarget: null,
          sources: ['crt.sh'],
        },
      ],
    }

    const approvedOrigins = new Set(['https://app.corp.example'])
    const applied = applyDiscoveredSubdomainsToRun(store, created.id, discovery, approvedOrigins)
    assert.deepEqual(applied.admittedOrigins, ['https://x.app.corp.example'])
    assert.equal(approvedOrigins.has('https://x.app.corp.example'), true)
    assert.equal(approvedOrigins.has('https://admin.app.corp.example'), false)
    assert.equal(approvedOrigins.has('https://api.corp.example'), false)
    assert.equal(approvedOrigins.has('https://other.corp.example'), false)

    const afterRun = store.run(created.id)
    assert.equal(afterRun.scopeRevision, revAfterScope + 1, 'auto-admission must bump scopeRevision')
    assert.equal(afterRun.approved.includes(apiCand.id), false)
    assert.equal(afterRun.approved.includes(adminCand.id), false)

    const autoEvent = store.client
      .prepare('SELECT kind, detail FROM events WHERE run_id = ? AND kind = ?')
      .get(created.id, 'asset.auto_admitted') as { kind: string; detail: string | null } | undefined
    assert.ok(autoEvent, 'asset.auto_admitted event must be recorded')
    const detail = JSON.parse(autoEvent.detail ?? '{}') as Record<string, unknown>
    assert.equal(detail.origin, 'https://x.app.corp.example')
    assert.equal(detail.anchor, 'app.corp.example')
    assert.equal(detail.scopeRevision, revAfterScope + 1)

    // Operator explicitly approving a previously declined host in a subsequent setScope clears it
    store.command({
      requestId: randomUUID(),
      runId: created.id,
      action: 'scope',
      assetIds: [appSeed.id, adminCand.id],
      expectedScopeRevision: afterRun.scopeRevision,
      consent: true,
      capabilityTier: 1,
    })
    assert.equal(store.runsRepo.isOriginDeclined(created.id, 'https://admin.app.corp.example'), false)
    assert.equal(store.runsRepo.isOriginDeclined(created.id, 'https://api.corp.example'), true)
    store.close()
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('H-39 sibling: variant-sweep path resolver and sibling walker refuse sensitive repo entries', t => {
  const reposDir = tempDir('kovo-h39-sibling-')
  t.after(() => rmSync(reposDir, { recursive: true, force: true }))
  const repoRoot = join(reposDir, 'acme', 'demo')
  mkdirSync(join(repoRoot, 'src'), { recursive: true })
  mkdirSync(join(repoRoot, '.ssh'), { recursive: true })
  mkdirSync(join(repoRoot, '.git'), { recursive: true })
  mkdirSync(join(repoRoot, 'credentials'), { recursive: true })

  const token = 'db.queryUnsafe('
  writeFileSync(join(repoRoot, 'src', 'primary.ts'), `export function a() { return ${token}'x') }\n`)
  writeFileSync(join(repoRoot, 'src', 'sibling.ts'), `export function b() { return ${token}'y') }\n`)
  writeFileSync(join(repoRoot, '.env'), `SECRET=${token}\n`)
  writeFileSync(join(repoRoot, '.env.production.js'), `module.exports = { call: "${token}" }\n`)
  writeFileSync(join(repoRoot, '.ssh', 'helper.ts'), `// ${token}\n`)
  writeFileSync(join(repoRoot, '.git', 'config'), `[remote "origin"]\nurl = ${token}\n`)
  writeFileSync(join(repoRoot, 'credentials', 'prod.json'), `{"k":"${token}"}\n`)
  writeFileSync(join(repoRoot, 'server.key'), `${token}\n`)

  assert.equal(isSensitiveRepoEntry('.env', '.env', false), true)
  assert.equal(isSensitiveRepoEntry('.env.production.js', '.env.production.js', false), true)
  assert.equal(isSensitiveRepoEntry('.ssh', '.ssh', true), true)
  assert.equal(isSensitiveRepoRelativePath('.ssh/helper.ts'), true)
  assert.equal(isSensitiveRepoRelativePath('.git/config'), true)
  assert.equal(isSensitiveRepoRelativePath('src/sibling.ts'), false)

  assert.equal(resolveSafeVariantSweepFile(repoRoot, '.env.production.js'), null)
  assert.equal(resolveSafeVariantSweepFile(repoRoot, '.ssh/helper.ts'), null)
  assert.equal(resolveSafeVariantSweepFile(repoRoot, '.git/config'), null)
  assert.equal(resolveSafeVariantSweepFile(repoRoot, 'server.key'), null)
  assert.equal(resolveSafeVariantSweepLocation(reposDir, 'acme/demo', '.env.production.js', ['/repos/acme/demo']), null)
  assert.notEqual(resolveSafeVariantSweepFile(repoRoot, 'src/sibling.ts'), null)

  const hits = collectVariantSweepSiblingHits(
    reposDir,
    ['/repos/acme/demo'],
    [token],
    [{ repo: 'acme/demo', file: 'src/primary.ts', startLine: 1, endLine: 1 }],
  )
  assert.deepEqual(hits.map(h => h.file), ['src/sibling.ts'])
})

test('C1 path canonicalization: allows %2F in query parameters while rejecting unsafe pathname syntax and query control chars', () => {
  const oauthQuery = '/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&next=%2Fs%2F123'
  assert.equal(hasUnsafeAdmissionPath(oauthQuery), false)
  assert.equal(canonicalPathAndQuery(oauthQuery), oauthQuery)
  assert.equal(hasUnsafeAdmissionPath('https://idp.example' + oauthQuery), false)
  assert.equal(canonicalPathAndQuery('https://idp.example' + oauthQuery), oauthQuery)

  for (const unsafe of [
    '/api/../admin',
    '/api/%2e%2e/admin',
    '/api/%2fadmin',
    '/api/%5cadmin',
    '/api\\admin',
    'https://idp.example/api/%2e%2e/admin?ok=1',
    '/authorize?next=ok\r\nX-Injected: 1',
    '/authorize?next=ok\0',
  ]) {
    assert.equal(hasUnsafeAdmissionPath(unsafe), true, `expected unsafe: ${unsafe}`)
    assert.equal(canonicalPathAndQuery(unsafe), null, `expected null canonical: ${unsafe}`)
  }
})
