import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import { Store } from '../src/server/store.ts'
import {
  COMMON_SUBDOMAIN_PREFIXES,
  discoverSubdomainsForOrigins,
  extractCertspotterCandidates,
  extractHackerTargetCandidates,
  runDiscoverySubdomainsForRun,
  type SubdomainDnsResolver,
} from '../src/server/subdomain-discovery.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

function tempStore(prefix: string): { dir: string; store: Store } {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  return { dir, store: new Store(dir) }
}

test('crt.sh 502 retries once fast and succeeds; persistent crt.sh 502/timeout falls back to Certspotter + HackerTarget + DNS sweep', async () => {
  // Part A: crt.sh returns 502 once then 200 on fast retry
  let crtAttempts = 0
  const retryFetch: typeof fetch = async input => {
    const url = String(input)
    if (url.includes('crt.sh')) {
      crtAttempts += 1
      if (crtAttempts === 1) return new Response('Bad Gateway', { status: 502 })
      return new Response(JSON.stringify([{ name_value: 'alpha.retry-test.example' }]), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }
    if (url.includes('certspotter.com')) {
      return new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } })
    }
    return new Response('', { status: 200 })
  }
  const retryDns: SubdomainDnsResolver = async host => {
    if (host === 'alpha.retry-test.example') return { cnames: [], addresses: ['93.184.216.34'] }
    return { cnames: [], addresses: [] }
  }

  const retryRes = await discoverSubdomainsForOrigins(['https://retry-test.example'], {
    fetchImpl: retryFetch,
    dnsResolver: retryDns,
    retryDelayMs: 0,
  })
  assert.equal(crtAttempts, 2, 'crt.sh must perform 1 fast retry on 502')
  assert.equal(retryRes.warnings.length, 0)
  assert.deepEqual(retryRes.discovered.map(d => d.origin), ['https://alpha.retry-test.example'])

  // Part B: crt.sh fails with persistent 502 -> Certspotter + HackerTarget + common-prefix DNS sweep still discover all live subdomains
  let persistentCrtAttempts = 0
  const fallbackFetch: typeof fetch = async input => {
    const url = String(input)
    if (url.includes('crt.sh')) {
      persistentCrtAttempts += 1
      return new Response('Bad Gateway', { status: 502 })
    }
    if (url.includes('api.certspotter.com/v1/issuances')) {
      return new Response(JSON.stringify([
        { dns_names: ['dyad.example', '*.dyad.example', 'academy.dyad.example', 'dead-cs.dyad.example'] },
      ]), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    if (url.includes('api.hackertarget.com/hostsearch')) {
      return new Response(
        'dyad.example,76.76.21.21\nengine.dyad.example,76.76.21.21\nstatus.dyad.example,104.18.0.1\n',
        { status: 200, headers: { 'content-type': 'text/plain' } },
      )
    }
    return new Response('Not found', { status: 404 })
  }

  const liveMap: Record<string, { cnames: string[]; addresses: string[] }> = {
    'www.dyad.example': { cnames: ['cname.vercel-dns.com'], addresses: ['76.76.21.21'] },
    'app.dyad.example': { cnames: ['cname.vercel-dns.com'], addresses: ['76.76.21.21'] },
    'api.dyad.example': { cnames: [], addresses: ['34.120.1.1'] },
    'academy.dyad.example': { cnames: [], addresses: ['76.76.21.22'] },
    'engine.dyad.example': { cnames: ['dyad-engine.fly.dev'], addresses: ['66.241.124.1'] },
    'status.dyad.example': { cnames: ['dyad.statuspage.io'], addresses: ['104.18.0.1'] },
  }
  const fallbackDns: SubdomainDnsResolver = async host => liveMap[host] ?? { cnames: [], addresses: [] }

  const fallbackRes = await discoverSubdomainsForOrigins(['https://dyad.example'], {
    fetchImpl: fallbackFetch,
    dnsResolver: fallbackDns,
    retryDelayMs: 0,
  })
  assert.equal(persistentCrtAttempts, 2, 'crt.sh should retry once on persistent 502')
  assert.equal(fallbackRes.warnings.length, 1)
  assert.ok(fallbackRes.warnings[0]!.includes('502'))

  const origins = fallbackRes.discovered.map(d => d.origin).sort()
  assert.deepEqual(origins, [
    'https://academy.dyad.example',
    'https://api.dyad.example',
    'https://app.dyad.example',
    'https://engine.dyad.example',
    'https://status.dyad.example',
    'https://www.dyad.example',
  ])

  const statusEntry = fallbackRes.discovered.find(d => d.origin === 'https://status.dyad.example')!
  assert.equal(statusEntry.thirdParty, true)
  assert.equal(statusEntry.thirdPartyVendor, 'statuspage.io')

  const engineEntry = fallbackRes.discovered.find(d => d.origin === 'https://engine.dyad.example')!
  assert.equal(engineEntry.thirdParty, false)
  assert.ok(engineEntry.sources?.includes('hackertarget'))

  const appEntry = fallbackRes.discovered.find(d => d.origin === 'https://app.dyad.example')!
  assert.ok(appEntry.sources?.includes('dns_sweep'))
})

test('when EVERY external CT API times out or is rate-limited, wildcard-safe DNS sweep still finds real live subdomains', async () => {
  const allFailFetch: typeof fetch = async input => {
    const url = String(input)
    if (url.includes('crt.sh')) throw new DOMException('The operation was aborted due to timeout', 'TimeoutError')
    if (url.includes('certspotter')) return new Response('rate limited', { status: 429 })
    if (url.includes('hackertarget')) return new Response('API count exceeded - Increase Quota with Membership', { status: 200 })
    return new Response('', { status: 500 })
  }

  const liveHosts = new Set([
    'www.outage.example',
    'api.outage.example',
    'app.outage.example',
    'docs.outage.example',
    'mcp.outage.example',
    'cloud.outage.example',
  ])
  const dns: SubdomainDnsResolver = async host => {
    if (liveHosts.has(host)) {
      return {
        cnames: host === 'docs.outage.example' ? ['hosting.gitbook.io'] : [],
        addresses: ['93.184.216.34'],
      }
    }
    return { cnames: [], addresses: [] }
  }

  const res = await discoverSubdomainsForOrigins(['https://outage.example'], {
    fetchImpl: allFailFetch,
    dnsResolver: dns,
    retryDelayMs: 0,
  })
  assert.equal(res.warnings.length, 1)
  assert.ok(res.warnings[0]!.includes('crt.sh'))
  assert.ok(res.warnings[0]!.includes('certspotter'))
  assert.ok(res.warnings[0]!.includes('hackertarget'))
  assert.deepEqual(
    res.discovered.map(d => d.origin).sort(),
    [...liveHosts].map(h => `https://${h}`).sort(),
  )
  assert.equal(res.discovered.find(d => d.origin === 'https://docs.outage.example')?.thirdParty, true)
  assert.equal(res.discovered.find(d => d.origin === 'https://mcp.outage.example')?.thirdParty, false)
})

test('wildcard DNS detection: when random label resolves, common-prefix sweep is skipped cleanly so 0 fake subdomains are returned', async () => {
  const probedHosts: string[] = []
  const emptyFetch: typeof fetch = async input => {
    const url = String(input)
    if (url.includes('hackertarget')) return new Response('', { status: 200 })
    return new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } })
  }
  const wildcardDns: SubdomainDnsResolver = async host => {
    probedHosts.push(host)
    // Wildcard DNS: every *.wild.example resolves to the same IP
    if (host.endsWith('.wild.example')) {
      return { cnames: [], addresses: ['203.0.113.42'] }
    }
    return { cnames: [], addresses: [] }
  }

  const res = await discoverSubdomainsForOrigins(['https://wild.example'], {
    fetchImpl: emptyFetch,
    dnsResolver: wildcardDns,
    wildcardProbeLabel: 'kovo-nx-testprobe',
  })

  assert.deepEqual(res.wildcardApexes, ['wild.example'])
  assert.deepEqual(res.discovered, [], 'wildcard domain with empty passive CT must return 0 fake subdomains')
  assert.deepEqual(probedHosts, ['kovo-nx-testprobe.wild.example'], 'only the random wildcard probe should be queried')

  // Verify legitimate CT-observed hosts are still returned on wildcard DNS domains, without sweeping 60 prefixes
  probedHosts.length = 0
  const ctOnlyFetch: typeof fetch = async input => {
    const url = String(input)
    if (url.includes('crt.sh')) {
      return new Response(JSON.stringify([{ name_value: 'real-app.wild.example' }]), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }
    if (url.includes('certspotter')) return new Response('[]', { status: 200 })
    return new Response('', { status: 200 })
  }
  const resWithCt = await discoverSubdomainsForOrigins(['https://wild.example'], {
    fetchImpl: ctOnlyFetch,
    dnsResolver: wildcardDns,
    wildcardProbeLabel: 'kovo-nx-testprobe',
  })
  assert.deepEqual(resWithCt.discovered.map(d => d.origin), ['https://real-app.wild.example'])
  assert.equal(probedHosts.includes('admin.wild.example'), false, 'common prefixes must not be swept on wildcard DNS')
})

test('union/dedupe across all sources, HackerTarget rate-limit filtering, third-party CNAME classification, and raised 80-candidate default', async () => {
  // Parser checks
  const cs = extractCertspotterCandidates(
    [{ dns_names: ['*.api.union.example', 'API.UNION.EXAMPLE.', 'evil.other.example', 'union.example'] }],
    'union.example',
    new Set(['union.example']),
  )
  assert.deepEqual(cs, ['api.union.example'])

  const htRateLimited = extractHackerTargetCandidates(
    'API count exceeded - Increase Quota with Membership',
    'union.example',
    new Set(['union.example']),
  )
  assert.deepEqual(htRateLimited.hosts, [])
  assert.ok(htRateLimited.rateLimitedOrError?.includes('API count exceeded'))

  const htParsed = extractHackerTargetCandidates(
    'union.example,1.1.1.1\napi.union.example,1.1.1.1\nblog.union.example,2.2.2.2\nAPI count exceeded\nnot-a-valid-line\n',
    'union.example',
    new Set(['union.example']),
  )
  assert.deepEqual(htParsed.hosts.sort(), ['api.union.example', 'blog.union.example'])
  assert.equal(htParsed.rateLimitedOrError, null)

  // Verify default maxCandidates >= 80 and common prefix list has ~60 unique entries
  assert.ok(COMMON_SUBDOMAIN_PREFIXES.length >= 55)
  assert.equal(new Set(COMMON_SUBDOMAIN_PREFIXES).size, COMMON_SUBDOMAIN_PREFIXES.length)

  const dnsLookups = new Map<string, number>()
  const multiFetch: typeof fetch = async input => {
    const url = String(input)
    if (url.includes('crt.sh')) {
      return new Response(JSON.stringify([
        { name_value: 'shared.union.example\ncrt-only.union.example\nhelp.union.example' },
        ...Array.from({ length: 65 }, (_, i) => ({ name_value: `svc-${String(i + 1).padStart(2, '0')}.union.example` })),
      ]), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    if (url.includes('certspotter')) {
      return new Response(JSON.stringify([
        { dns_names: ['shared.union.example', 'cs-only.union.example', 'docs.union.example'] },
      ]), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    if (url.includes('hackertarget')) {
      return new Response(
        'shared.union.example,93.184.216.1\nht-only.union.example,93.184.216.2\n',
        { status: 200 },
      )
    }
    return new Response('', { status: 404 })
  }

  const multiDns: SubdomainDnsResolver = async host => {
    dnsLookups.set(host, (dnsLookups.get(host) ?? 0) + 1)
    if (host.startsWith('kovo-nx-')) return { cnames: [], addresses: [] }
    if (host === 'help.union.example') return { cnames: ['union.zendesk.com'], addresses: ['104.16.53.111'] }
    if (host === 'docs.union.example') return { cnames: ['union.readme.io'], addresses: ['35.186.245.1'] }
    if (host === 'shared.union.example') return { cnames: ['union.vercel.app'], addresses: ['76.76.21.21'] }
    if (host === 'crt-only.union.example' || host === 'cs-only.union.example' || host === 'ht-only.union.example' || host === 'api.union.example' || /^svc-\d+\.union\.example$/.test(host)) {
      return { cnames: [], addresses: ['93.184.216.34'] }
    }
    return { cnames: [], addresses: [] }
  }

  const res = await discoverSubdomainsForOrigins(['https://union.example'], {
    fetchImpl: multiFetch,
    dnsResolver: multiDns,
  })

  // Must find > 40 (old cap) and up to 80 (new default cap) without duplicates
  assert.ok(res.discovered.length > 60 && res.discovered.length <= 80, `expected >60 and <=80, got ${res.discovered.length}`)
  assert.equal(new Set(res.discovered.map(d => d.origin)).size, res.discovered.length)

  // Shared host discovered by all 3 passive sources is deduped and only resolved ONCE in DNS
  const shared = res.discovered.find(d => d.origin === 'https://shared.union.example')
  assert.ok(shared)
  assert.equal(shared.thirdParty, false)
  assert.equal(dnsLookups.get('shared.union.example'), 1, 'duplicate candidate across sources must only resolve DNS once')
  assert.ok(shared.sources?.includes('crt.sh'))
  assert.ok(shared.sources?.includes('certspotter'))
  assert.ok(shared.sources?.includes('hackertarget'))

  // Third-party SaaS CNAMEs preserved
  assert.equal(res.discovered.find(d => d.origin === 'https://help.union.example')?.thirdParty, true)
  assert.equal(res.discovered.find(d => d.origin === 'https://docs.union.example')?.thirdParty, true)
  assert.ok(res.discovered.some(d => d.origin === 'https://crt-only.union.example'))
  assert.ok(res.discovered.some(d => d.origin === 'https://cs-only.union.example'))
  assert.ok(res.discovered.some(d => d.origin === 'https://ht-only.union.example'))
  assert.ok(res.discovered.some(d => d.origin === 'https://api.union.example'))
})

test('runDiscoverySubdomainsForRun persists discovered subdomains into project_assets and run.candidates before scope review, and skips local-lab/prepared/non-public seeds', async () => {
  const { dir, store } = tempStore('kovo-ux-sub-run-')
  try {
    // 1. Public project -> discovers subdomains and populates run.candidates BEFORE scope approval
    const pubProj = store.createProject({
      requestId: randomUUID(),
      name: 'Dyad Public',
      seeds: ['https://dyad.example'],
      environment: 'public',
    })
    const pubRun = store.createRun({
      requestId: randomUUID(),
      projectId: pubProj.id,
      goal: 'Review dyad.example and subdomains',
      sourceMode: 'public',
      capabilityTier: 1,
      budgetUsd: 5,
      budgetRequests: 0,
      maxRpsPerOrigin: 3,
      workerConcurrency: 2,
      workerMaxTurns: 20,
    })
    store.command({ requestId: randomUUID(), runId: pubRun.id, action: 'discover', consent: true })

    const stubFetch: typeof fetch = async input => {
      const url = String(input)
      if (url.includes('crt.sh')) return new Response('Bad Gateway', { status: 502 })
      if (url.includes('certspotter')) {
        return new Response(JSON.stringify([{ dns_names: ['academy.dyad.example', 'docs.dyad.example'] }]), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      if (url.includes('hackertarget')) return new Response('api.dyad.example,76.76.21.21\n', { status: 200 })
      return new Response('', { status: 404 })
    }
    const stubDns: SubdomainDnsResolver = async host => {
      switch (host) {
        case 'www.dyad.example': return { cnames: ['cname.vercel-dns.com'], addresses: ['76.76.21.21'] }
        case 'app.dyad.example': return { cnames: ['cname.vercel-dns.com'], addresses: ['76.76.21.21'] }
        case 'api.dyad.example': return { cnames: [], addresses: ['76.76.21.22'] }
        case 'academy.dyad.example': return { cnames: [], addresses: ['76.76.21.23'] }
        case 'docs.dyad.example': return { cnames: ['hosting.gitbook.io'], addresses: ['104.18.0.1'] }
        default: return { cnames: [], addresses: [] }
      }
    }

    const res = await runDiscoverySubdomainsForRun(store, pubRun.id, {
      fetchImpl: stubFetch,
      dnsResolver: stubDns,
      retryDelayMs: 0,
    })

    assert.equal(res.skipped, false)
    assert.deepEqual([...res.addedOrigins].sort(), [
      'https://academy.dyad.example',
      'https://api.dyad.example',
      'https://app.dyad.example',
      'https://docs.dyad.example',
      'https://www.dyad.example',
    ])
    assert.deepEqual(res.thirdPartyOrigins, ['https://docs.dyad.example'])
    assert.equal(res.totalCandidates, 6) // seed + 5 discovered

    // Verify run is in scope review with ALL discovered subdomains visible immediately
    const reviewRun = store.run(pubRun.id)
    assert.equal(reviewRun.phase, 'review')
    assert.equal(reviewRun.status, 'waiting')
    assert.equal(reviewRun.approved.length, 0, 'candidates stay unapproved until operator approves scope')
    assert.deepEqual(reviewRun.candidates.map(c => c.origin).sort(), [
      'https://academy.dyad.example',
      'https://api.dyad.example',
      'https://app.dyad.example',
      'https://docs.dyad.example',
      'https://dyad.example',
      'https://www.dyad.example',
    ])
    const docsCand = reviewRun.candidates.find(c => c.origin === 'https://docs.dyad.example')!
    assert.equal(docsCand.thirdParty, true)
    assert.deepEqual(docsCand.dnsSource?.externalAliases, ['hosting.gitbook.io'])
    assert.ok(docsCand.sourceEvidenceId, 'discovered candidates should link to discovery worker inventory evidence')

    // Persisted into project_assets too
    const assets = store.projectDetail(pubProj.id).assets
    assert.equal(assets.length, 6)
    assert.ok(assets.some(a => a.origin === 'https://academy.dyad.example'))

    // Idempotent re-run adds 0 duplicates
    const secondRes = await runDiscoverySubdomainsForRun(store, pubRun.id, {
      fetchImpl: stubFetch,
      dnsResolver: stubDns,
      retryDelayMs: 0,
    })
    assert.deepEqual(secondRes.addedOrigins, [])
    assert.equal(store.run(pubRun.id).candidates.length, 6)

    // 2. Prepared run on public project -> skipped with zero network calls
    let skippedNetworkCalls = 0
    const failOnCallFetch: typeof fetch = async () => {
      skippedNetworkCalls += 1
      return new Response('[]', { status: 200 })
    }
    const failOnCallDns: SubdomainDnsResolver = async () => {
      skippedNetworkCalls += 1
      return { cnames: [], addresses: ['1.2.3.4'] }
    }

    const prepRun = store.createRun({
      requestId: randomUUID(),
      projectId: pubProj.id,
      goal: 'Offline prepared check',
      sourceMode: 'prepared',
      capabilityTier: 0,
      budgetUsd: 5,
      budgetRequests: 0,
      maxRpsPerOrigin: 3,
      workerConcurrency: 2,
      workerMaxTurns: 20,
    })
    store.command({ requestId: randomUUID(), runId: prepRun.id, action: 'discover', consent: true })
    const prepRes = await runDiscoverySubdomainsForRun(store, prepRun.id, {
      fetchImpl: failOnCallFetch,
      dnsResolver: failOnCallDns,
    })
    assert.equal(prepRes.skipped, true)
    assert.equal(prepRes.reason, 'prepared_source_mode')
    assert.equal(skippedNetworkCalls, 0)

    // 3. local-lab project -> skipped with zero network calls
    const prevAllowLab = process.env.KOVO_ALLOW_LOCAL_LAB
    process.env.KOVO_ALLOW_LOCAL_LAB = '1'
    try {
      const labProj = store.createProject({
        requestId: randomUUID(),
        name: 'Local Lab Target',
        seeds: ['http://127.0.0.1:4101'],
        environment: 'local-lab',
      })
      const labRun = store.createRun({
        requestId: randomUUID(),
        projectId: labProj.id,
        goal: 'Local lab assessment',
        sourceMode: 'public',
        capabilityTier: 1,
        budgetUsd: 5,
        budgetRequests: 0,
        maxRpsPerOrigin: 3,
        workerConcurrency: 2,
        workerMaxTurns: 20,
      })
      store.command({ requestId: randomUUID(), runId: labRun.id, action: 'discover', consent: true })
      const labRes = await runDiscoverySubdomainsForRun(store, labRun.id, {
        fetchImpl: failOnCallFetch,
        dnsResolver: failOnCallDns,
      })
      assert.equal(labRes.skipped, true)
      assert.equal(labRes.reason, 'non_public_environment')
      assert.equal(skippedNetworkCalls, 0)
    } finally {
      if (prevAllowLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
      else process.env.KOVO_ALLOW_LOCAL_LAB = prevAllowLab
    }
  } finally {
    store.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

test('actions.ts wires auto-discovery in createRun and subdomain discovery in commandRun', () => {
  const actionsSrc = readFileSync(join(REPO_ROOT, 'src', 'actions.ts'), 'utf8')
  assert.match(actionsSrc, /import\s*\{[^}]*\brunDiscoverySubdomainsForRun\b[^}]*\}\s*from\s*'\.\/server\/subdomain-discovery\.ts'/)
  assert.match(actionsSrc, /export const createRun[\s\S]*?action:\s*'discover'[\s\S]*?runDiscoverySubdomainsForRun\(/)
  assert.match(actionsSrc, /export const commandRun[\s\S]*?data\.action === 'discover'[\s\S]*?runDiscoverySubdomainsForRun\(/)
})
