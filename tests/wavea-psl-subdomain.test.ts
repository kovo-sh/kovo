import assert from 'node:assert/strict'
import test from 'node:test'
import {
  icannRegistrableDomain,
  isMultiTenantPublicSuffix,
  isPublicSuffixHost,
  publicSuffixSection,
  registrableApex,
  registrableDomain,
} from '../src/server/public-suffix.ts'
import {
  apexDomainOfHost,
  classifyThirdPartyCname,
  discoverSubdomainsForOrigins,
  extractDiscoverableApex,
  formatSubdomainOrigin,
  isSharedPaasHost,
  isSharedPaasOrigin,
  rankDiscoveredAssets,
  rankScopeAssets,
  type SubdomainDnsResolver,
} from '../src/server/subdomain-discovery.ts'

test('PSL private-section detector flags multi-tenant PaaS suffixes automatically while preserving ICANN multi-part ccTLDs', () => {
  // Broad set of PSL PRIVATE suffixes — including platforms never in the legacy 43-entry list
  const privatePslHosts = [
    'my-app.vercel.app',
    'sub.my-app.vercel.app',
    'vercel.app',
    'bar.github.io',
    'api.fly.dev',
    'site.pages.dev',
    'app.herokuapp.com',
    'd111111abcdef8.cloudfront.net',
    'bucket.s3.amazonaws.com',
    'foo.netlify.app',
    'svc.onrender.com',
    'edge.workers.dev',
    'contoso.azurewebsites.net',
    'demo.appspot.com',
    'svc-abc-uc.a.run.app',
    'tenant.awsapprunner.com',
    'db.tenant.aivencloud.com',
    'site.framer.ai',
    'shop.bubbleapps.io',
    'site.carrd.co',
    'blog.blogspot.com',
    'home.no-ip.co.uk',
    'app.deno.dev',
    'portal.replit.app',
    'demo.surge.sh',
    'demo.pythonanywhere.com',
    'tunnel.ngrok-free.app',
    // Supplemental PSL-gap C-2 parity hosts
    'web.railway.app',
    'svc.amazonaws.com',
    'demo.glitch.me',
  ]

  for (const host of privatePslHosts) {
    assert.equal(isMultiTenantPublicSuffix(host), true, `expected ${host} to be a multi-tenant PSL private host`)
    assert.equal(publicSuffixSection(host), 'private', `expected ${host} section to be private`)
    assert.equal(isSharedPaasHost(host), true, `expected isSharedPaasHost(${host}) === true`)
    assert.equal(isSharedPaasOrigin(`https://${host}`), true)
    assert.equal(apexDomainOfHost(host), null, `expected shared-tenant host ${host} to refuse apex collapse`)
    assert.equal(extractDiscoverableApex(`https://${host}`), null)
  }

  // ICANN multi-part ccTLDs & standard domains MUST remain first-party discoverable
  const icannHosts: Array<[string, string]> = [
    ['acme.co.uk', 'acme.co.uk'],
    ['api.acme.co.uk', 'acme.co.uk'],
    ['deep.staging.acme.co.uk', 'acme.co.uk'],
    ['portal.acme.com.au', 'acme.com.au'],
    ['app.corp.co.jp', 'corp.co.jp'],
    ['shop.example.com.br', 'example.com.br'],
    ['api.example.com.co', 'example.com.co'],
    ['app.example.com', 'example.com'],
    ['www.ck', 'www.ck'],
    ['city.kawasaki.jp', 'city.kawasaki.jp'],
  ]

  for (const [host, expectedApex] of icannHosts) {
    assert.equal(isMultiTenantPublicSuffix(host), false, `expected ICANN host ${host} NOT to be multi-tenant`)
    assert.equal(publicSuffixSection(host), 'icann', `expected ${host} section to be icann`)
    assert.equal(isSharedPaasHost(host), false)
    assert.equal(apexDomainOfHost(host), expectedApex)
    assert.equal(registrableApex(host), expectedApex)
    assert.equal(extractDiscoverableApex(`https://${host}`), expectedApex)
  }

  // Bare ICANN public suffixes are never discoverable apexes
  for (const bareSuffix of ['co.uk', 'com.au', 'org.uk', 'com.co', 'gov.uk']) {
    assert.equal(isPublicSuffixHost(bareSuffix), true)
    assert.equal(isMultiTenantPublicSuffix(bareSuffix), false)
    assert.equal(apexDomainOfHost(bareSuffix), null)
    assert.equal(registrableApex(bareSuffix), null)
  }
})

test('universal CNAME apex ownership check flags unknown third-party vendors while keeping same-apex and pure CDN/PaaS proxies first-party', async () => {
  // Unknown / unlisted third-party vendor CNAMEs are caught automatically without any hardcoded vendor list
  const unlisted = classifyThirdPartyCname(['acme.unlisted-vendor.io'], 'help.acme.com')
  assert.equal(unlisted.thirdParty, true)
  assert.equal(unlisted.externalCname, true)
  assert.equal(unlisted.matchedVendor, 'unlisted-vendor.io')
  assert.equal(unlisted.cnameApex, 'unlisted-vendor.io')
  assert.equal(unlisted.cnameTarget, 'acme.unlisted-vendor.io')

  // Multi-part ccTLD unknown third-party vendor
  const ukVendor = classifyThirdPartyCname(['boards.unknown-ats.com.au'], 'careers.acme.co.uk')
  assert.equal(ukVendor.thirdParty, true)
  assert.equal(ukVendor.externalCname, true)
  assert.equal(ukVendor.matchedVendor, 'unknown-ats.com.au')
  assert.equal(ukVendor.cnameApex, 'unknown-ats.com.au')

  // Multi-hop CNAME chain: same-apex first hop followed by external third-party hop
  const chained = classifyThirdPartyCname(
    ['help-alias.acme.com', 'acme-portal.obscure-helpdesk.dev'],
    'support.acme.com',
  )
  assert.equal(chained.thirdParty, true)
  assert.equal(chained.externalCname, true)
  assert.equal(chained.matchedVendor, 'obscure-helpdesk.dev')
  assert.equal(chained.cnameTarget, 'acme-portal.obscure-helpdesk.dev')

  // PSL private SaaS vendors (gitbook.io, myshopify.com, webflow.io, notion.site) resolve their ICANN vendor apex
  for (const [cname, expectedVendor] of [
    ['hosting.gitbook.io', 'gitbook.io'],
    ['shops.myshopify.com', 'myshopify.com'],
    ['proxy-ssl.webflow.io', 'webflow.io'],
    ['custom.notion.site', 'notion.site'],
    ['acme.statuspage.io', 'statuspage.io'],
    ['acme.zendesk.com', 'zendesk.com'],
  ] as const) {
    const res = classifyThirdPartyCname([cname], 'docs.acme.co.uk')
    assert.equal(res.thirdParty, true, `expected ${cname} to classify as third-party`)
    assert.equal(res.externalCname, true)
    assert.equal(res.matchedVendor, expectedVendor)
    assert.equal(icannRegistrableDomain(cname), expectedVendor)
  }

  // Same-apex CNAMEs stay first-party (including multi-part ccTLDs)
  const sameApexUk = classifyThirdPartyCname(['edge-lb.internal.acme.co.uk'], 'api.acme.co.uk')
  assert.equal(sameApexUk.thirdParty, false)
  assert.equal(sameApexUk.externalCname, false)
  assert.equal(sameApexUk.matchedVendor, null)
  assert.equal(sameApexUk.cnameApex, 'acme.co.uk')

  // Pure CDN / edge / first-party PaaS proxies stay first-party
  const firstPartyProxies = [
    'cname.vercel-dns.com',
    'my-app.vercel.app',
    'd111111abcdef8.cloudfront.net',
    'acme-api.onrender.com',
    'acme-web.fly.dev',
    'acme-prod.netlify.app',
    'dualstack.a.sni.global.fastly.net',
    'acme.co.uk.cdn.cloudflare.net',
    'acme-api.us-east-1.elb.amazonaws.com',
    'acme-portal.azurewebsites.net',
    'acme-svc-abc-uc.a.run.app',
  ]
  for (const proxy of firstPartyProxies) {
    const res = classifyThirdPartyCname([proxy], 'app.acme.co.uk')
    assert.equal(res.thirdParty, false, `expected pure CDN/PaaS proxy ${proxy} to stay first-party`)
    assert.equal(res.externalCname, false)
    assert.equal(res.matchedVendor, null)
  }

  // End-to-end discoverSubdomainsForOrigins wires targetHost into universal CNAME apex check
  const stubFetch: typeof fetch = async input => {
    const url = String(input)
    if (url.includes('crt.sh')) {
      return new Response(
        JSON.stringify([
          { name_value: 'help.acme.co.uk\napi.acme.co.uk\napp.acme.co.uk' },
        ]),
        { status: 200, headers: { 'content-type': 'application/json' } },
      )
    }
    if (url.includes('certspotter')) return new Response('[]', { status: 200 })
    return new Response('', { status: 200 })
  }
  const stubDns: SubdomainDnsResolver = async host => {
    switch (host) {
      case 'help.acme.co.uk':
        return { cnames: ['acme.unlisted-vendor.io'], addresses: ['198.51.100.10'] }
      case 'api.acme.co.uk':
        return { cnames: ['lb.acme.co.uk'], addresses: ['198.51.100.11'] }
      case 'app.acme.co.uk':
        return { cnames: ['cname.vercel-dns.com'], addresses: ['76.76.21.21'] }
      default:
        return { cnames: [], addresses: [] }
    }
  }

  const res = await discoverSubdomainsForOrigins(['https://acme.co.uk'], {
    fetchImpl: stubFetch,
    dnsResolver: stubDns,
    retryDelayMs: 0,
  })
  assert.deepEqual(res.queriedApexes, ['acme.co.uk'])
  const help = res.discovered.find(d => d.hostname === 'help.acme.co.uk')!
  assert.equal(help.thirdParty, true)
  assert.equal(help.thirdPartyVendor, 'unlisted-vendor.io')
  assert.equal(help.cnameTarget, 'acme.unlisted-vendor.io')

  const api = res.discovered.find(d => d.hostname === 'api.acme.co.uk')!
  assert.equal(api.thirdParty, false)
  assert.equal(api.thirdPartyVendor, null)

  const app = res.discovered.find(d => d.hostname === 'app.acme.co.uk')!
  assert.equal(app.thirdParty, false)
})

test('subdomain discovery preserves explicit non-443 staging ports and http scheme (plus explicit local sweep without public CT calls)', async () => {
  // Unit checks for formatSubdomainOrigin & extractDiscoverableApex
  assert.equal(extractDiscoverableApex('https://staging.corp.example:8443'), 'corp.example')
  assert.equal(extractDiscoverableApex('http://staging.corp.example:8080'), 'corp.example')
  assert.equal(extractDiscoverableApex('http://corp.example'), 'corp.example')
  assert.equal(extractDiscoverableApex('https://staging.acme.co.uk:8443'), 'acme.co.uk')
  assert.equal(formatSubdomainOrigin('api.corp.example', 'https://staging.corp.example:8443'), 'https://api.corp.example:8443')
  assert.equal(formatSubdomainOrigin('api.corp.example', 'http://staging.corp.example:8080'), 'http://api.corp.example:8080')
  assert.equal(formatSubdomainOrigin('api.corp.example', 'https://corp.example:443'), 'https://api.corp.example')
  assert.equal(formatSubdomainOrigin('api.corp.example', 'http://corp.example:80'), 'http://api.corp.example')
  assert.equal(formatSubdomainOrigin('api.internal.local', 'http://portal.internal.local:8080'), 'http://api.internal.local:8080')

  // Local/internal domains skipped by default, accepted with explicit allowLocal: true
  assert.equal(extractDiscoverableApex('http://internal.local:8080'), null)
  assert.equal(extractDiscoverableApex('http://portal.internal.local:8080', { allowLocal: true }), 'internal.local')
  assert.equal(extractDiscoverableApex('http://internal.local:8080', { allowLocal: true }), 'internal.local')

  // Localhost and IP literals are ALWAYS skipped even with allowLocal: true
  for (const neverDiscoverable of [
    'http://localhost:3000',
    'https://localhost',
    'http://127.0.0.1:4101',
    'https://[::1]:8443',
    'https://10.0.0.15:8080',
    'ftp://corp.example',
  ]) {
    assert.equal(extractDiscoverableApex(neverDiscoverable), null)
    assert.equal(extractDiscoverableApex(neverDiscoverable, { allowLocal: true }), null)
  }

  // Part A: https://staging.corp.example:8443 preserves scheme + :8443 on all discovered origins
  const stagingFetch: typeof fetch = async input => {
    const url = String(input)
    if (url.includes('crt.sh')) {
      return new Response(
        JSON.stringify([{ name_value: 'api.corp.example\nadmin.corp.example\nstaging.corp.example' }]),
        { status: 200, headers: { 'content-type': 'application/json' } },
      )
    }
    if (url.includes('certspotter')) return new Response('[]', { status: 200 })
    return new Response('', { status: 200 })
  }
  const stagingDns: SubdomainDnsResolver = async host => {
    if (host === 'api.corp.example' || host === 'admin.corp.example') {
      return { cnames: [], addresses: ['198.51.100.44'] }
    }
    return { cnames: [], addresses: [] }
  }

  const stagingRes = await discoverSubdomainsForOrigins(['https://staging.corp.example:8443'], {
    fetchImpl: stagingFetch,
    dnsResolver: stagingDns,
    retryDelayMs: 0,
  })
  assert.deepEqual(stagingRes.queriedApexes, ['corp.example'])
  assert.deepEqual(
    stagingRes.discovered.map(d => d.origin).sort(),
    ['https://admin.corp.example:8443', 'https://api.corp.example:8443'],
  )
  assert.equal(stagingRes.discovered[0]!.parentOrigin, 'https://staging.corp.example:8443')

  // Part B: http://portal.internal.local:8080 with allowLocal: true runs DNS sweep only (0 public CT HTTP calls)
  let publicCtFetchCalls = 0
  const localFetch: typeof fetch = async () => {
    publicCtFetchCalls += 1
    return new Response('[]', { status: 200 })
  }
  const localDns: SubdomainDnsResolver = async host => {
    if (host === 'api.internal.local' || host === 'auth.internal.local') {
      return { cnames: [], addresses: ['10.20.30.40'] }
    }
    return { cnames: [], addresses: [] }
  }

  const localRes = await discoverSubdomainsForOrigins(['http://portal.internal.local:8080'], {
    allowLocal: true,
    fetchImpl: localFetch,
    dnsResolver: localDns,
  })
  assert.equal(publicCtFetchCalls, 0, 'local/internal apex must never leak to public internet CT APIs')
  assert.deepEqual(localRes.queriedApexes, ['internal.local'])
  assert.deepEqual(
    localRes.discovered.map(d => d.origin).sort(),
    ['http://api.internal.local:8080', 'http://auth.internal.local:8080'],
  )
})

test('canonical PSL-backed registrableApex and rankScopeAssets handle .co.uk, .com.au, nested subdomains, sprawl, and shared-PaaS isolation', () => {
  assert.equal(rankDiscoveredAssets, rankScopeAssets)
  assert.equal(registrableApex('https://staging.api.acme.co.uk:8443/v1'), 'acme.co.uk')
  assert.equal(registrableApex('https://checkout.shop.acme.com.au'), 'acme.com.au')
  assert.equal(registrableApex('api.acme.co.uk'), 'acme.co.uk')
  assert.equal(registrableApex('co.uk'), null)
  assert.equal(registrableApex('com.au'), null)
  assert.equal(registrableApex('vercel.app'), null)
  assert.equal(registrableApex('https://sub.my-app.vercel.app'), 'my-app.vercel.app')
  assert.equal(registrableDomain('api.acme.co.uk'), 'acme.co.uk')

  // Multi-part ccTLD (.co.uk) ranking with nested subdomains, sprawl, third-party CNAME, and foreign apex
  const candidates = [
    { id: 'c-sprawl', origin: 'https://pr-42.acme.co.uk', source: 'subdomain_discovery', thirdParty: false },
    { id: 'c-3p', origin: 'https://help.acme.co.uk', source: 'subdomain_discovery', thirdParty: true },
    { id: 'c-deep', origin: 'https://v2.api.acme.co.uk', source: 'subdomain_discovery', thirdParty: false },
    { id: 'c-api', origin: 'https://api.acme.co.uk', source: 'subdomain_discovery', thirdParty: false },
    { id: 'c-seed', origin: 'https://app.acme.co.uk', source: 'Project seed', thirdParty: false },
    { id: 'c-apex', origin: 'https://acme.co.uk', source: 'subdomain_discovery', thirdParty: false },
    { id: 'c-staging', origin: 'https://staging.acme.co.uk:8443', source: 'subdomain_discovery', thirdParty: false },
    { id: 'c-foreign', origin: 'https://api.other-company.com.au', source: 'subdomain_discovery', thirdParty: false },
  ]

  const ranked = rankScopeAssets(candidates, ['https://app.acme.co.uk'])
  const ids = ranked.map(r => r.asset.id)

  // Seed first, then exact apex, then Tier-1 api (depth 1), then deep Tier-1 v2.api (depth 2) / Tier-2 staging,
  // then noisy sprawl, and foreign/third-party last
  assert.equal(ids[0], 'c-seed')
  assert.equal(ids[1], 'c-apex')
  assert.equal(ids[2], 'c-api')
  assert.ok(ids.indexOf('c-api') < ids.indexOf('c-deep'), 'shallow api.acme.co.uk must outrank nested v2.api.acme.co.uk')
  assert.ok(ids.indexOf('c-staging') < ids.indexOf('c-sprawl'), 'staging must outrank pr-42 preview sprawl')
  assert.ok(ids.indexOf('c-sprawl') < ids.indexOf('c-3p'), 'first-party sprawl must outrank third-party CNAME')

  // Verify PSL-relative depth parity between .co.uk and .com
  const apiUk = ranked.find(r => r.asset.id === 'c-api')!
  const deepUk = ranked.find(r => r.asset.id === 'c-deep')!
  const apexUk = ranked.find(r => r.asset.id === 'c-apex')!
  const foreignAu = ranked.find(r => r.asset.id === 'c-foreign')!
  assert.equal(apexUk.depth, 0)
  assert.equal(apexUk.apex, 'acme.co.uk')
  assert.equal(apexUk.sameApexAsSeed, true)
  assert.equal(apiUk.depth, 1)
  assert.equal(apiUk.sameApexAsSeed, true)
  assert.equal(deepUk.depth, 2)
  assert.equal(foreignAu.apex, 'other-company.com.au')
  assert.equal(foreignAu.sameApexAsSeed, false)

  // Shared-PaaS tenant isolation in rankScopeAssets: sibling tenant on vercel.app is NEVER sameApexAsSeed
  const paasRanked = rankScopeAssets(
    [
      { id: 'own', origin: 'https://my-app.vercel.app', source: 'Project seed', thirdParty: false },
      { id: 'sibling', origin: 'https://other-tenant.vercel.app', source: 'subdomain_discovery', thirdParty: false },
    ],
    ['https://my-app.vercel.app'],
  )
  assert.equal(paasRanked.find(r => r.asset.id === 'own')?.sameApexAsSeed, true)
  assert.equal(paasRanked.find(r => r.asset.id === 'sibling')?.sameApexAsSeed, false)

  // maxAssets and includeThirdParty filtering options work cleanly
  const top3FirstParty = rankScopeAssets(candidates, ['https://app.acme.co.uk'], {
    includeThirdParty: false,
    maxAssets: 3,
  })
  assert.equal(top3FirstParty.length, 3)
  assert.equal(top3FirstParty.some(r => r.asset.thirdParty), false)
})
