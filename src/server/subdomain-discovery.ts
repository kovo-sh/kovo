import { resolve4, resolve6, resolveCname } from 'node:dns/promises'
import { isIP } from 'node:net'
import type { Candidate, DnsSource } from '../domain.ts'
import type { Run, Store } from './store.ts'

export interface DnsLookupResult {
  cnames: string[]
  addresses: string[]
}

export type SubdomainDnsResolver = (hostname: string, signal?: AbortSignal) => Promise<DnsLookupResult>

export interface ThirdPartyCnameClassification {
  thirdParty: boolean
  matchedVendor: string | null
  cnameTarget: string | null
}

export interface DiscoveredSubdomain {
  hostname: string
  origin: string
  parentOrigin: string
  apexDomain: string
  cnames: string[]
  addresses: string[]
  thirdParty: boolean
  thirdPartyVendor: string | null
  cnameTarget: string | null
}

export interface SubdomainDiscoveryOptions {
  fetchImpl?: typeof fetch
  dnsResolver?: SubdomainDnsResolver
  ctTimeoutMs?: number
  dnsTimeoutMs?: number
  dnsConcurrency?: number
  maxCandidates?: number
  signal?: AbortSignal
}

export interface SubdomainDiscoveryResult {
  discovered: DiscoveredSubdomain[]
  queriedApexes: string[]
  skippedOrigins: string[]
  warnings: string[]
}

/**
 * Conservative managed third-party SaaS CNAME suffix list.
 * First-party PaaS/CDN hosting providers (Vercel, Cloudflare, CloudFront, Render, Fly, Netlify,
 * Fastly, AWS/GCP/Azure) are intentionally excluded so first-party apps hosted on them stay
 * eligible for wildcard subdomain admission.
 */
export const THIRD_PARTY_SAAS_CNAME_SUFFIXES: readonly string[] = [
  'statuspage.io',
  'gitbook.io',
  'zendesk.com',
  'intercom.io',
  'helpscoutdocs.com',
  'freshdesk.com',
  'atlassian.net',
  'hubspot.net',
  'myshopify.com',
  'squarespace.com',
  'webflow.io',
  'ghost.io',
  'notion.site',
  'mailgun.org',
  'sendgrid.net',
  'googlehosted.com',
  'readme.io',
]

const MULTI_PART_PUBLIC_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'co.in', 'net.in', 'org.in', 'gov.in',
  'co.kr', 'or.kr', 'go.kr',
  'com.mx', 'org.mx', 'gob.mx',
  'com.sg', 'org.sg', 'gov.sg',
  'com.hk', 'org.hk', 'gov.hk',
  'com.tw', 'org.tw', 'gov.tw',
  'co.za', 'org.za', 'gov.za',
  'co.il', 'org.il', 'gov.il',
  'com.tr', 'org.tr', 'gov.tr',
  'com.ar', 'com.co', 'com.my', 'com.ph', 'com.vn', 'com.ua', 'com.pl',
])

const SKIPPED_LOCAL_SUFFIXES = ['.localhost', '.local', '.internal', '.test', '.invalid', '.home.arpa']
const VALID_HOSTNAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/
const PRIORITY_PREFIXES = ['www', 'api', 'app', 'auth', 'admin', 'portal', 'dashboard', 'account', 'accounts', 'login', 'sso', 'staging', 'dev', 'docs', 'blog', 'status']

const DEFAULT_CT_TIMEOUT_MS = 8_000
const DEFAULT_DNS_TIMEOUT_MS = 3_000
const DEFAULT_DNS_CONCURRENCY = 8
const DEFAULT_MAX_CANDIDATES = 40

function normalizeHostname(raw: string): string {
  return raw.trim().toLowerCase().replace(/\.+$/, '')
}

function isLocalOrNonPublicHost(hostname: string): boolean {
  const host = normalizeHostname(hostname)
  if (!host || host === 'localhost' || !host.includes('.')) return true
  if (host.startsWith('[') && host.endsWith(']')) return true
  if (isIP(host) !== 0) return true
  for (const suffix of SKIPPED_LOCAL_SUFFIXES) {
    if (host.endsWith(suffix)) return true
  }
  return false
}

export function apexDomainOfHost(hostname: string): string | null {
  const host = normalizeHostname(hostname)
  if (isLocalOrNonPublicHost(host) || !VALID_HOSTNAME_RE.test(host)) return null
  const labels = host.split('.')
  if (labels.length < 2) return null
  const lastTwo = `${labels[labels.length - 2]}.${labels[labels.length - 1]}`
  if (MULTI_PART_PUBLIC_SUFFIXES.has(lastTwo)) {
    if (labels.length < 3) return null
    return `${labels[labels.length - 3]}.${lastTwo}`
  }
  return lastTwo
}

/**
 * Returns the public apex domain for an HTTPS origin on the default port (443), or `null` when
 * the origin is localhost, an IP literal, `.local`/`.internal`/`.test`/`.invalid`, plain HTTP, or
 * uses a non-standard port (such as local-lab/benchmark containers).
 */
export function extractDiscoverableApex(origin: string): string | null {
  let url: URL
  try {
    url = new URL(origin)
  } catch {
    return null
  }
  if (url.protocol !== 'https:') return null
  if (url.port !== '' && url.port !== '443') return null
  return apexDomainOfHost(url.hostname)
}

export function isPublicDiscoverableOrigin(origin: string): boolean {
  return extractDiscoverableApex(origin) !== null
}

/**
 * Classify a resolved CNAME chain against conservative managed third-party SaaS vendor suffixes.
 * First-party PaaS/CDN providers remain `thirdParty: false`.
 */
export function classifyThirdPartyCname(cnames: readonly string[]): ThirdPartyCnameClassification {
  let firstCname: string | null = null
  for (const raw of cnames) {
    const target = normalizeHostname(raw)
    if (!target) continue
    firstCname ??= target
    for (const suffix of THIRD_PARTY_SAAS_CNAME_SUFFIXES) {
      if (target === suffix || target.endsWith(`.${suffix}`)) {
        return { thirdParty: true, matchedVendor: suffix, cnameTarget: target }
      }
    }
  }
  return { thirdParty: false, matchedVendor: null, cnameTarget: firstCname }
}

function candidateRank(hostname: string, apex: string): [number, number, string] {
  const prefix = hostname.slice(0, -(apex.length + 1))
  const priorityIdx = PRIORITY_PREFIXES.indexOf(prefix)
  const depth = prefix.split('.').length
  return [priorityIdx >= 0 ? priorityIdx : PRIORITY_PREFIXES.length + depth, hostname.length, hostname]
}

export function extractCtCandidates(
  entries: readonly { name_value?: unknown; common_name?: unknown }[],
  apex: string,
  excludedHosts: ReadonlySet<string>,
  maxCandidates = DEFAULT_MAX_CANDIDATES,
): string[] {
  const normalizedApex = normalizeHostname(apex)
  const suffix = `.${normalizedApex}`
  const found = new Set<string>()

  const consider = (raw: string) => {
    for (const piece of raw.split(/[\r\n\s,]+/)) {
      let host = normalizeHostname(piece)
      if (!host) continue
      if (host.startsWith('*.')) host = host.slice(2)
      if (!host || host.includes('*') || host.includes('@')) continue
      if (!host.endsWith(suffix)) continue
      if (host.length > 253 || !VALID_HOSTNAME_RE.test(host)) continue
      if (excludedHosts.has(host)) continue
      found.add(host)
    }
  }

  for (const entry of entries) {
    if (typeof entry?.name_value === 'string') consider(entry.name_value)
    if (typeof entry?.common_name === 'string') consider(entry.common_name)
  }

  const wwwHost = `www.${normalizedApex}`
  if (!excludedHosts.has(wwwHost) && VALID_HOSTNAME_RE.test(wwwHost)) {
    found.add(wwwHost)
  }

  const sorted = [...found].sort((a, b) => {
    const [ar0, ar1, ar2] = candidateRank(a, normalizedApex)
    const [br0, br1, br2] = candidateRank(b, normalizedApex)
    if (ar0 !== br0) return ar0 - br0
    if (ar1 !== br1) return ar1 - br1
    return ar2.localeCompare(br2)
  })
  return sorted.slice(0, Math.max(1, Math.min(Math.floor(maxCandidates), 200)))
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, fallback: T): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      promise,
      new Promise<T>(resolve => {
        timer = setTimeout(() => resolve(fallback), timeoutMs)
        timer.unref?.()
      }),
    ])
  } catch {
    return fallback
  } finally {
    if (timer) clearTimeout(timer)
  }
}

export async function defaultSubdomainDnsResolver(
  hostname: string,
  signal?: AbortSignal,
  timeoutMs = DEFAULT_DNS_TIMEOUT_MS,
): Promise<DnsLookupResult> {
  if (signal?.aborted) return { cnames: [], addresses: [] }
  const [cnames, ipv4, ipv6] = await Promise.all([
    withTimeout(resolveCname(hostname).catch(() => [] as string[]), timeoutMs, [] as string[]),
    withTimeout(resolve4(hostname).catch(() => [] as string[]), timeoutMs, [] as string[]),
    withTimeout(resolve6(hostname).catch(() => [] as string[]), timeoutMs, [] as string[]),
  ])
  return {
    cnames: cnames.map(normalizeHostname).filter(Boolean),
    addresses: [...ipv4, ...ipv6].filter(Boolean),
  }
}

async function mapWithConcurrency<T, R>(
  items: readonly T[],
  concurrency: number,
  worker: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length)
  let nextIdx = 0
  const runners = Array.from({ length: Math.min(Math.max(1, concurrency), items.length) }, async () => {
    while (nextIdx < items.length) {
      const idx = nextIdx
      nextIdx += 1
      results[idx] = await worker(items[idx]!)
    }
  })
  await Promise.all(runners)
  return results
}

/**
 * Passive CT-log (`crt.sh`) + live DNS subdomain discovery for public HTTPS origins.
 * Skips localhost, IP literals, `.local`/`.internal`/`.test`/`.invalid`, HTTP, and non-standard
 * ports with zero network calls. Gracefully degrades on CT-log errors/rate-limits/offline.
 */
export async function discoverSubdomainsForOrigins(
  origins: readonly string[],
  options: SubdomainDiscoveryOptions = {},
): Promise<SubdomainDiscoveryResult> {
  const fetchFn = options.fetchImpl ?? fetch
  const ctTimeoutMs = Math.max(500, Math.min(options.ctTimeoutMs ?? DEFAULT_CT_TIMEOUT_MS, 20_000))
  const dnsTimeoutMs = Math.max(500, Math.min(options.dnsTimeoutMs ?? DEFAULT_DNS_TIMEOUT_MS, 10_000))
  const dnsConcurrency = Math.max(1, Math.min(options.dnsConcurrency ?? DEFAULT_DNS_CONCURRENCY, 16))
  const maxCandidates = Math.max(1, Math.min(options.maxCandidates ?? DEFAULT_MAX_CANDIDATES, 200))
  const dnsResolver: SubdomainDnsResolver = options.dnsResolver
    ?? ((host, sig) => defaultSubdomainDnsResolver(host, sig, dnsTimeoutMs))

  const skippedOrigins: string[] = []
  const excludedHosts = new Set<string>()
  const apexToParent = new Map<string, string>()

  for (const origin of origins) {
    try {
      const parsed = new URL(origin)
      excludedHosts.add(normalizeHostname(parsed.hostname))
    } catch {
      skippedOrigins.push(origin)
      continue
    }
    const apex = extractDiscoverableApex(origin)
    if (!apex) {
      skippedOrigins.push(origin)
      continue
    }
    if (!apexToParent.has(apex)) {
      apexToParent.set(apex, origin)
    }
  }

  if (apexToParent.size === 0 || options.signal?.aborted) {
    return { discovered: [], queriedApexes: [], skippedOrigins, warnings: [] }
  }

  const queriedApexes = [...apexToParent.keys()]
  const warnings: string[] = []
  const discovered: DiscoveredSubdomain[] = []
  const seenOrigins = new Set<string>(origins)

  for (const apex of queriedApexes) {
    if (options.signal?.aborted) break
    const parentOrigin = apexToParent.get(apex)!
    let ctEntries: Array<{ name_value?: unknown; common_name?: unknown }> = []

    try {
      const reqSignal = options.signal
        ? AbortSignal.any([options.signal, AbortSignal.timeout(ctTimeoutMs)])
        : AbortSignal.timeout(ctTimeoutMs)
      const url = `https://crt.sh/?q=%25.${encodeURIComponent(apex)}&output=json`
      const res = await fetchFn(url, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          'User-Agent': 'KovoHunter/2 passive subdomain discovery',
        },
        signal: reqSignal,
      })
      if (!res.ok) {
        warnings.push(`crt.sh returned HTTP ${res.status} for ${apex}; falling back to www probe only.`)
      } else {
        const parsed = await res.json().catch(() => null)
        if (Array.isArray(parsed)) {
          ctEntries = parsed as Array<{ name_value?: unknown; common_name?: unknown }>
        } else {
          warnings.push(`crt.sh returned non-array payload for ${apex}.`)
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'CT lookup failed'
      warnings.push(`crt.sh lookup failed for ${apex}: ${msg.slice(0, 140)}`)
    }

    const candidates = extractCtCandidates(ctEntries, apex, excludedHosts, maxCandidates)
    if (candidates.length === 0) continue

    const resolved = await mapWithConcurrency(candidates, dnsConcurrency, async hostname => {
      if (options.signal?.aborted) return null
      try {
        const dns = await withTimeout(
          dnsResolver(hostname, options.signal),
          dnsTimeoutMs,
          { cnames: [], addresses: [] },
        )
        const cnames = (dns.cnames ?? []).map(normalizeHostname).filter(Boolean)
        const addresses = (dns.addresses ?? []).filter(Boolean)
        if (cnames.length === 0 && addresses.length === 0) return null
        const classification = classifyThirdPartyCname(cnames)
        return {
          hostname,
          origin: `https://${hostname}`,
          parentOrigin,
          apexDomain: apex,
          cnames,
          addresses,
          thirdParty: classification.thirdParty,
          thirdPartyVendor: classification.matchedVendor,
          cnameTarget: classification.cnameTarget,
        } satisfies DiscoveredSubdomain
      } catch {
        return null
      }
    })

    for (const item of resolved) {
      if (!item || seenOrigins.has(item.origin)) continue
      seenOrigins.add(item.origin)
      discovered.push(item)
    }
  }

  return { discovered, queriedApexes, skippedOrigins, warnings }
}

export interface AppliedSubdomainDiscovery {
  admitted: Candidate[]
  candidatesOnly: Candidate[]
  thirdParty: Candidate[]
  admittedOrigins: string[]
  candidateOrigins: string[]
  thirdPartyOrigins: string[]
}

function buildDnsSource(sub: DiscoveredSubdomain): DnsSource {
  const recordTypes: ('A' | 'AAAA' | 'CNAME')[] = []
  if (sub.cnames.length > 0) recordTypes.push('CNAME')
  if (sub.addresses.some(addr => !addr.includes(':'))) recordTypes.push('A')
  if (sub.addresses.some(addr => addr.includes(':'))) recordTypes.push('AAAA')
  if (recordTypes.length === 0) recordTypes.push('A')
  return {
    zone: sub.apexDomain,
    recordTypes,
    externalAliases: sub.thirdParty && sub.cnameTarget ? [sub.cnameTarget] : [],
  }
}

/**
 * Apply Phase-0 discovered subdomains to a run:
 * - When an approved first-party parent asset for the apex has `includeSubdomains: true` AND the
 *   subdomain is NOT a third-party SaaS CNAME (`!sub.thirdParty`), admit `https://<subdomain>`
 *   into `run.approved` and `project_assets` (`source: 'phase0_ct_discovery'`, `thirdParty: false`)
 *   so Phase-0 crawls and workers test it in the SAME run.
 * - Otherwise (`sub.thirdParty` or strict single-host parent), record as an unapproved candidate
 *   only (never auto-admitted or actively probed unless the operator explicitly approves it).
 */
export function applyDiscoveredSubdomainsToRun(
  storage: Store,
  runId: string,
  result: SubdomainDiscoveryResult,
  approvedOrigins: Set<string>,
): AppliedSubdomainDiscovery {
  const run = storage.run(runId)
  const detail = storage.projectDetail(run.projectId)
  const wildcardApexes = new Set<string>()
  for (const asset of detail.assets) {
    if (!asset.includeSubdomains || asset.thirdParty) continue
    if (!approvedOrigins.has(asset.origin)) continue
    const apex = extractDiscoverableApex(asset.origin)
    if (apex) wildcardApexes.add(apex)
  }

  const admitted: Candidate[] = []
  const candidatesOnly: Candidate[] = []
  const thirdParty: Candidate[] = []
  const admittedOrigins: string[] = []
  const candidateOrigins: string[] = []
  const thirdPartyOrigins: string[] = []

  for (const sub of result.discovered) {
    if (approvedOrigins.has(sub.origin)) continue
    const dnsSource = buildDnsSource(sub)
    const shouldAutoAdmit = !sub.thirdParty && wildcardApexes.has(sub.apexDomain)

    const latestRun: Run = storage.run(runId)
    storage.suggestCandidateHost(latestRun, sub.origin, 'phase0_ct_discovery', sub.thirdParty, dnsSource)
    const withCand = storage.run(runId)
    const cand = withCand.candidates.find(c => c.origin === sub.origin)
    if (!cand) continue

    if (shouldAutoAdmit) {
      if (!withCand.approved.includes(cand.id)) {
        storage.updateRun(runId, { approved: [...withCand.approved, cand.id] })
      }
      approvedOrigins.add(sub.origin)
      admitted.push(cand)
      admittedOrigins.push(sub.origin)
    } else {
      candidatesOnly.push(cand)
      candidateOrigins.push(sub.origin)
      if (sub.thirdParty) {
        thirdParty.push(cand)
        thirdPartyOrigins.push(sub.origin)
      }
    }
  }

  storage.event(
    runId,
    'phase0.subdomains_discovered',
    `Passive CT discovery checked ${result.queriedApexes.length} apex ${result.queriedApexes.length === 1 ? 'domain' : 'domains'}: ${result.discovered.length} live (${admittedOrigins.length} auto-admitted, ${candidateOrigins.length} candidate-only, ${thirdPartyOrigins.length} third-party CNAME).`,
    {
      queriedApexes: result.queriedApexes,
      skippedOrigins: result.skippedOrigins,
      discoveredCount: result.discovered.length,
      admittedCount: admittedOrigins.length,
      candidateCount: candidateOrigins.length,
      thirdPartyCount: thirdPartyOrigins.length,
      admittedOrigins,
      candidateOrigins,
      thirdPartyOrigins,
      warnings: result.warnings,
    },
  )

  return { admitted, candidatesOnly, thirdParty, admittedOrigins, candidateOrigins, thirdPartyOrigins }
}
