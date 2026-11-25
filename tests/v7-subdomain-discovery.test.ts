import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { Store } from '../src/server/store.ts'
import {
  apexDomainOfHost,
  applyDiscoveredSubdomainsToRun,
  classifyThirdPartyCname,
  discoverSubdomainsForOrigins,
  extractCtCandidates,
  extractDiscoverableApex,
  THIRD_PARTY_SAAS_CNAME_SUFFIXES,
  type SubdomainDnsResolver,
} from '../src/server/subdomain-discovery.ts'

function tempStore(prefix: string): { dir: string; store: Store } {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  return { dir, store: new Store(dir) }
}

test('local-lab, localhost, IP literals, internal suffixes, HTTP, and non-standard ports skip with zero network calls', async () => {
  let fetchCalls = 0
  let dnsCalls = 0
  const stubFetch: typeof fetch = async () => {
    fetchCalls += 1
    return new Response('[]', { status: 200 })
  }
  const stubDns: SubdomainDnsResolver = async () => {
    dnsCalls += 1
    return { cnames: [], addresses: ['93.184.216.34'] }
  }

  const skippedInputs = [
    'http://localhost:3000',
    'https://localhost',
    'http://127.0.0.1:4101',
    'https://127.0.0.1',
    'https://[::1]',
    'https://10.0.0.15',
    'https://shopflow.local',
    'https://api.service.internal',
    'https://app.acme.test',
    'https://staging.acme.invalid',
    'http://example.com',
    'https://example.com:8443',
  ]

  for (const origin of skippedInputs) {
    assert.equal(extractDiscoverableApex(origin), null, `expected ${origin} to be skipped`)
  }
  assert.equal(extractDiscoverableApex('https://app.example.com'), 'example.com')
  assert.equal(extractDiscoverableApex('https://app.acme.co.uk'), 'acme.co.uk')
  assert.equal(apexDomainOfHost('api.shop.example.com'), 'example.com')

  const result = await discoverSubdomainsForOrigins(skippedInputs, {
    fetchImpl: stubFetch,
    dnsResolver: stubDns,
  })
  assert.equal(fetchCalls, 0)
  assert.equal(dnsCalls, 0)
  assert.deepEqual(result.queriedApexes, [])
  assert.deepEqual(result.discovered, [])
  assert.equal(result.skippedOrigins.length, skippedInputs.length)
})

test('CT candidate parsing normalizes wildcards, dedupes, includes www, filters invalid/foreign hosts, and caps at 40', () => {
  const entries = [
    { name_value: '*.api.acme.example\napi.acme.example\nAPP.ACME.EXAMPLE.', common_name: 'auth.acme.example' },
    { name_value: 'evil.otherdomain.example\nnot a host\nuser@acme.example\nacme.example' },
    ...Array.from({ length: 80 }, (_, i) => ({
      name_value: `svc-${String(i + 1).padStart(3, '0')}.acme.example`,
    })),
  ]

  const excluded = new Set(['acme.example'])
  const candidates = extractCtCandidates(entries, 'acme.example', excluded, 40)

  assert.equal(candidates.length, 40)
  assert.equal(new Set(candidates).size, 40)
  assert.ok(candidates.includes('www.acme.example'))
  assert.ok(candidates.includes('api.acme.example'))
  assert.ok(candidates.includes('app.acme.example'))
  assert.ok(candidates.includes('auth.acme.example'))
  assert.equal(candidates.some(h => h.includes('*') || h.includes('@') || !h.endsWith('.acme.example')), false)
  assert.equal(candidates.includes('acme.example'), false)
})

test('classifyThirdPartyCname flags managed vendor SaaS CNAMEs while keeping first-party hosting/CDN CNAMEs first-party', () => {
  // Every curated managed vendor SaaS suffix must classify as thirdParty: true
  for (const suffix of THIRD_PARTY_SAAS_CNAME_SUFFIXES) {
    const exact = classifyThirdPartyCname([suffix])
    assert.equal(exact.thirdParty, true, `expected ${suffix} to be third-party`)
    assert.equal(exact.matchedVendor, suffix)

    const nested = classifyThirdPartyCname([`customer-123.${suffix}.`])
    assert.equal(nested.thirdParty, true, `expected customer-123.${suffix} to be third-party`)
    assert.equal(nested.matchedVendor, suffix)
    assert.equal(nested.cnameTarget, `customer-123.${suffix}`)
  }

  // First-party PaaS / CDN hosting CNAMEs must remain thirdParty: false
  const firstPartyCnames = [
    'cname.vercel-dns.com',
    'my-app.vercel.app',
    'd111111abcdef8.cloudfront.net',
    'acme-api.onrender.com',
    'acme-web.fly.dev',
    'acme-prod.netlify.app',
    'dualstack.a.sni.global.fastly.net',
    'example.com.cdn.cloudflare.net',
    'acme-api.us-east-1.elb.amazonaws.com',
    'acme-portal.azurewebsites.net',
    'acme-svc-abc-uc.a.run.app',
  ]
  for (const cname of firstPartyCnames) {
    const res = classifyThirdPartyCname([cname])
    assert.equal(res.thirdParty, false, `expected first-party PaaS/CDN ${cname} to stay thirdParty: false`)
    assert.equal(res.matchedVendor, null)
    assert.equal(res.cnameTarget, cname)
  }
})

test('discoverSubdomainsForOrigins degrades gracefully on crt.sh 429/5xx and resolves live DNS with CNAME classification', async () => {
  const stubFetch429: typeof fetch = async () => new Response('Rate limited', { status: 429 })
  const stubDns: SubdomainDnsResolver = async host => {
    if (host === 'www.acme.example') return { cnames: ['cname.vercel-dns.com'], addresses: ['76.76.21.21'] }
    return { cnames: [], addresses: [] }
  }

  const degraded = await discoverSubdomainsForOrigins(['https://acme.example'], {
    fetchImpl: stubFetch429,
    dnsResolver: stubDns,
  })
  assert.deepEqual(degraded.queriedApexes, ['acme.example'])
  assert.equal(degraded.warnings.length, 1)
  assert.ok(degraded.warnings[0]!.includes('429'))
  assert.equal(degraded.discovered.length, 1)
  assert.equal(degraded.discovered[0]!.origin, 'https://www.acme.example')
  assert.equal(degraded.discovered[0]!.thirdParty, false)
})

test('wildcard *.domain opt-in auto-admits first-party subdomains while keeping third-party CNAMEs unapproved candidates', async () => {
  const { dir, store } = tempStore('guardian-sub-wildcard-')
  try {
    const proj = store.createProject({
      requestId: randomUUID(),
      name: 'Wildcard SaaS',
      seeds: ['https://acme.example'],
      environment: 'public',
      includeSubdomains: true,
    })

    // Seed asset must have includeSubdomains persisted as true
    const detail = store.projectDetail(proj.id)
    assert.equal(detail.assets.length, 1)
    assert.equal(detail.assets[0]!.includeSubdomains, true)

    const created = store.createRun({
      requestId: randomUUID(),
      projectId: proj.id,
      goal: 'Assess acme.example and subdomains',
      sourceMode: 'public',
      capabilityTier: 1,
      budgetUsd: 5,
      budgetRequests: 0,
      maxRpsPerOrigin: 3,
      workerConcurrency: 2,
      workerMaxTurns: 20,
    })
    store.command({ requestId: randomUUID(), runId: created.id, action: 'discover', consent: true })
    const reviewRun = store.run(created.id)
    const seedCand = reviewRun.candidates.find(c => c.origin === 'https://acme.example')!
    store.command({
      requestId: randomUUID(),
      runId: created.id,
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

    const ctPayload = [
      { name_value: 'api.acme.example\napp.acme.example\ndocs.acme.example\nshop.acme.example\ndead.acme.example' },
    ]
    const stubFetch: typeof fetch = async () => new Response(JSON.stringify(ctPayload), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
    const stubDns: SubdomainDnsResolver = async host => {
      switch (host) {
        case 'api.acme.example': return { cnames: ['acme-api.onrender.com'], addresses: ['216.24.57.1'] }
        case 'app.acme.example': return { cnames: ['cname.vercel-dns.com'], addresses: ['76.76.21.21'] }
        case 'www.acme.example': return { cnames: [], addresses: ['93.184.216.34'] }
        case 'docs.acme.example': return { cnames: ['hosting.gitbook.io'], addresses: ['104.18.0.1'] }
        case 'shop.acme.example': return { cnames: ['shops.myshopify.com'], addresses: ['23.227.38.74'] }
        default: return { cnames: [], addresses: [] } // NXDOMAIN / dead
      }
    }

    const approvedOrigins = new Set(['https://acme.example'])
    const discovered = await discoverSubdomainsForOrigins([...approvedOrigins], {
      fetchImpl: stubFetch,
      dnsResolver: stubDns,
    })
    const applied = applyDiscoveredSubdomainsToRun(store, created.id, discovered, approvedOrigins)

    // First-party live subdomains (including PaaS/CDN CNAMEs) are auto-admitted
    assert.deepEqual([...applied.admittedOrigins].sort(), [
      'https://api.acme.example',
      'https://app.acme.example',
      'https://www.acme.example',
    ])
    for (const origin of applied.admittedOrigins) {
      assert.equal(approvedOrigins.has(origin), true)
    }

    // Third-party SaaS CNAMEs stay UNAPPROVED candidates with externalAliases recorded
    assert.deepEqual([...applied.thirdPartyOrigins].sort(), [
      'https://docs.acme.example',
      'https://shop.acme.example',
    ])
    assert.equal(approvedOrigins.has('https://docs.acme.example'), false)
    assert.equal(approvedOrigins.has('https://shop.acme.example'), false)

    const updatedRun = store.run(created.id)
    const approvedOriginSet = new Set(
      updatedRun.candidates.filter(c => updatedRun.approved.includes(c.id)).map(c => c.origin),
    )
    assert.equal(approvedOriginSet.has('https://api.acme.example'), true)
    assert.equal(approvedOriginSet.has('https://app.acme.example'), true)
    assert.equal(approvedOriginSet.has('https://docs.acme.example'), false)
    assert.equal(approvedOriginSet.has('https://shop.acme.example'), false)

    const docsCand = updatedRun.candidates.find(c => c.origin === 'https://docs.acme.example')
    assert.ok(docsCand)
    assert.equal(docsCand.thirdParty, true)
    assert.equal(docsCand.source, 'phase0_ct_discovery')
    assert.deepEqual(docsCand.dnsSource?.externalAliases, ['hosting.gitbook.io'])

    // Project assets persist the CNAME metadata and allow explicit operator approval later
    const postAssets = store.projectDetail(proj.id).assets
    const docsAsset = postAssets.find(a => a.origin === 'https://docs.acme.example')
    assert.ok(docsAsset)
    assert.equal(docsAsset.thirdParty, true)
    assert.equal(store.project(proj.id).defaultScope.includes('https://docs.acme.example'), false)

    const approvedRes = store.updateProjectAssetScope({
      requestId: randomUUID(),
      projectId: proj.id,
      assetId: docsAsset.id,
      approveInDefaultScope: true,
    })
    assert.equal(approvedRes.approvedInDefaultScope, true)
    assert.equal(store.project(proj.id).defaultScope.includes('https://docs.acme.example'), true)

    // phase0.subdomains_discovered event emitted with structured counts
    const subEvent = store.client
      .prepare('SELECT kind, detail FROM events WHERE run_id = ? AND kind = ?')
      .get(created.id, 'phase0.subdomains_discovered') as { kind: string; detail: string | null } | undefined
    assert.ok(subEvent)
    const data = JSON.parse(subEvent.detail ?? '{}') as Record<string, unknown>
    assert.equal(data.admittedCount, 3)
    assert.equal(data.thirdPartyCount, 2)
  } finally {
    store.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

test('strict single-host mode (includeSubdomains: false) keeps discovered subdomains as unapproved candidates only', async () => {
  const { dir, store } = tempStore('guardian-sub-strict-')
  try {
    const proj = store.createProject({
      requestId: randomUUID(),
      name: 'Strict Host',
      seeds: ['https://strict.example'],
      environment: 'public',
    })
    assert.equal(store.projectDetail(proj.id).assets[0]!.includeSubdomains, false)

    const created = store.createRun({
      requestId: randomUUID(),
      projectId: proj.id,
      goal: 'Assess strict.example only',
      sourceMode: 'public',
      capabilityTier: 1,
      budgetUsd: 5,
      budgetRequests: 0,
      maxRpsPerOrigin: 3,
      workerConcurrency: 2,
      workerMaxTurns: 20,
    })
    store.command({ requestId: randomUUID(), runId: created.id, action: 'discover', consent: true })
    const reviewRun = store.run(created.id)
    const seedCand = reviewRun.candidates[0]!
    store.command({
      requestId: randomUUID(),
      runId: created.id,
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

    const stubFetch: typeof fetch = async () => new Response(JSON.stringify([
      { name_value: 'api.strict.example' },
    ]), { status: 200, headers: { 'content-type': 'application/json' } })
    const stubDns: SubdomainDnsResolver = async host => ({
      cnames: [],
      addresses: host.endsWith('.strict.example') ? ['93.184.216.34'] : [],
    })

    const approvedOrigins = new Set(['https://strict.example'])
    const discovered = await discoverSubdomainsForOrigins([...approvedOrigins], {
      fetchImpl: stubFetch,
      dnsResolver: stubDns,
    })
    const applied = applyDiscoveredSubdomainsToRun(store, created.id, discovered, approvedOrigins)

    // Zero auto-admissions in strict single-host mode
    assert.deepEqual(applied.admittedOrigins, [])
    assert.equal(approvedOrigins.size, 1)
    assert.ok(applied.candidateOrigins.includes('https://api.strict.example'))

    const updatedRun = store.run(created.id)
    assert.equal(updatedRun.approved.length, 1)
    assert.ok(updatedRun.candidates.some(c => c.origin === 'https://api.strict.example'))
  } finally {
    store.close()
    rmSync(dir, { recursive: true, force: true })
  }
})
