import { randomBytes } from 'node:crypto'
import { resolve4, resolve6, resolveCname } from 'node:dns/promises'
import { isIP } from 'node:net'
import type { Candidate, DnsSource } from '../domain.ts'
import type { Run, Store } from './store.ts'

export interface DnsLookupResult {
  cnames: string[]
  addresses: string[]
}

export type SubdomainDnsResolver = (hostname: string, signal?: AbortSignal) => Promise<DnsLookupResult>

export type SubdomainDiscoverySource = 'crt.sh' | 'certspotter' | 'hackertarget' | 'dns_sweep'

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
  sources?: SubdomainDiscoverySource[]
}

export interface SubdomainDiscoveryOptions {
  fetchImpl?: typeof fetch
  dnsResolver?: SubdomainDnsResolver
  ctTimeoutMs?: number
  certspotterTimeoutMs?: number
  hackerTargetTimeoutMs?: number
  retryDelayMs?: number
  dnsTimeoutMs?: number
  dnsConcurrency?: number
  maxCandidates?: number
  wildcardProbeLabel?: string
  signal?: AbortSignal
}

export interface SubdomainDiscoveryResult {
  discovered: DiscoveredSubdomain[]
  queriedApexes: string[]
  skippedOrigins: string[]
  warnings: string[]
  wildcardApexes?: string[]
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

/**
 * Curated high-value first-party subdomain prefixes probed during wildcard-safe DNS sweeps
 * so discovery stays resilient even when every external passive CT API is rate-limited or down.
 */
export const COMMON_SUBDOMAIN_PREFIXES: readonly string[] = [
  'www', 'api', 'app', 'auth', 'login', 'sso', 'account', 'accounts', 'clerk',
  'admin', 'dashboard', 'console', 'portal', 'docs', 'blog', 'status', 'mail',
  'staging', 'stage', 'dev', 'beta', 'preview', 'sandbox', 'test',
  'cdn', 'static', 'assets', 'media', 'files', 'uploads',
  'ws', 'realtime', 'graphql', 'webhooks',
  'billing', 'pay', 'checkout', 'shop', 'store',
  'support', 'help', 'community', 'forum', 'careers', 'jobs', 'about',
  'chat', 'ai', 'cloud', 'mcp', 'hub', 'lab', 'studio', 'play', 'demo', 'academy',
  'internal', 'ops', 'git', 'code',
]

const CRT_RETRYABLE_STATUSES = new Set([429, 502, 503, 504])
const DEFAULT_CT_TIMEOUT_MS = 15_000
const DEFAULT_CERTSPOTTER_TIMEOUT_MS = 10_000
const DEFAULT_HACKERTARGET_TIMEOUT_MS = 8_000
const DEFAULT_RETRY_DELAY_MS = 350
const DEFAULT_DNS_TIMEOUT_MS = 3_000
const DEFAULT_DNS_CONCURRENCY = 12
const DEFAULT_MAX_CANDIDATES = 80
const DEFAULT_RUN_DISCOVERY_TIMEOUT_MS = 15_000
const DISCOVERY_USER_AGENT = 'KovoHunter/2 passive subdomain discovery'

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

function normalizeCandidateHost(raw: string, normalizedApex: string, excludedHosts: ReadonlySet<string>): string | null {
  const suffix = `.${normalizedApex}`
  let host = normalizeHostname(raw)
  if (!host) return null
  if (host.startsWith('*.')) host = host.slice(2)
  if (!host || host.includes('*') || host.includes('@')) return null
  if (!host.endsWith(suffix)) return null
  if (host.length > 253 || !VALID_HOSTNAME_RE.test(host)) return null
  if (excludedHosts.has(host)) return null
  return host
}

function rankAndCapCandidates(
  hosts: Iterable<string>,
  normalizedApex: string,
  maxCandidates: number,
): string[] {
  const deduped = [...new Set(hosts)]
  deduped.sort((a, b) => {
    const [ar0, ar1, ar2] = candidateRank(a, normalizedApex)
    const [br0, br1, br2] = candidateRank(b, normalizedApex)
    if (ar0 !== br0) return ar0 - br0
    if (ar1 !== br1) return ar1 - br1
    return ar2.localeCompare(br2)
  })
  return deduped.slice(0, Math.max(1, Math.min(Math.floor(maxCandidates), 200)))
}

function collectCtHosts(
  entries: readonly { name_value?: unknown; common_name?: unknown }[],
  normalizedApex: string,
  excludedHosts: ReadonlySet<string>,
): string[] {
  const found = new Set<string>()
  const consider = (raw: string) => {
    for (const piece of raw.split(/[\r\n\s,]+/)) {
      const host = normalizeCandidateHost(piece, normalizedApex, excludedHosts)
      if (host) found.add(host)
    }
  }
  for (const entry of entries) {
    if (typeof entry?.name_value === 'string') consider(entry.name_value)
    if (typeof entry?.common_name === 'string') consider(entry.common_name)
  }
  return [...found]
}

export function extractCtCandidates(
  entries: readonly { name_value?: unknown; common_name?: unknown }[],
  apex: string,
  excludedHosts: ReadonlySet<string>,
  maxCandidates = DEFAULT_MAX_CANDIDATES,
): string[] {
  const normalizedApex = normalizeHostname(apex)
  const found = new Set<string>(collectCtHosts(entries, normalizedApex, excludedHosts))

  const wwwHost = `www.${normalizedApex}`
  if (!excludedHosts.has(wwwHost) && VALID_HOSTNAME_RE.test(wwwHost)) {
    found.add(wwwHost)
  }

  return rankAndCapCandidates(found, normalizedApex, maxCandidates)
}

export function extractCertspotterCandidates(
  entries: readonly { dns_names?: unknown }[],
  apex: string,
  excludedHosts: ReadonlySet<string>,
  maxCandidates = DEFAULT_MAX_CANDIDATES,
): string[] {
  const normalizedApex = normalizeHostname(apex)
  const found = new Set<string>()
  for (const entry of entries) {
    if (!Array.isArray(entry?.dns_names)) continue
    for (const raw of entry.dns_names) {
      if (typeof raw !== 'string') continue
      const host = normalizeCandidateHost(raw, normalizedApex, excludedHosts)
      if (host) found.add(host)
    }
  }
  return rankAndCapCandidates(found, normalizedApex, maxCandidates)
}

export function extractHackerTargetCandidates(
  body: string,
  apex: string,
  excludedHosts: ReadonlySet<string>,
  maxCandidates = DEFAULT_MAX_CANDIDATES,
): { hosts: string[]; rateLimitedOrError: string | null } {
  const normalizedApex = normalizeHostname(apex)
  const trimmed = body.trim()
  if (!trimmed) return { hosts: [], rateLimitedOrError: null }
  if (/^(?:API count exceeded|error\b)/i.test(trimmed)) {
    return { hosts: [], rateLimitedOrError: trimmed.slice(0, 120) }
  }
  const found = new Set<string>()
  for (const line of trimmed.split(/\r?\n/)) {
    const cleanLine = line.trim()
    if (!cleanLine || /API count exceeded/i.test(cleanLine)) continue
    const commaIdx = cleanLine.indexOf(',')
    if (commaIdx <= 0) continue
    const hostToken = cleanLine.slice(0, commaIdx)
    const host = normalizeCandidateHost(hostToken, normalizedApex, excludedHosts)
    if (host) found.add(host)
  }
  return { hosts: rankAndCapCandidates(found, normalizedApex, maxCandidates), rateLimitedOrError: null }
}

function combineSignals(signal: AbortSignal | undefined, timeoutMs: number): AbortSignal {
  const timeoutSignal = AbortSignal.timeout(timeoutMs)
  return signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal
}

async function sleepAbortable(ms: number, signal?: AbortSignal): Promise<void> {
  if (ms <= 0 || signal?.aborted) return
  await new Promise<void>(resolve => {
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    timer.unref?.()
    const onAbort = () => {
      clearTimeout(timer)
      resolve()
    }
    signal?.addEventListener('abort', onAbort, { once: true })
  })
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
 * Multi-source resilient passive + wildcard-safe DNS subdomain discovery for public HTTPS origins:
 * - `crt.sh` (15s timeout, 1 fast retry on 429/502/503/504)
 * - Certspotter public issuances API (10s timeout)
 * - HackerTarget hostsearch API (8s timeout)
 * - Wildcard-safe common-prefix DNS sweep (~60 high-value prefixes, skipped if random label resolves)
 * Skips localhost, IP literals, `.local`/`.internal`/`.test`/`.invalid`, HTTP, and non-standard
 * ports with zero network calls. Gracefully degrades on CT-log errors/rate-limits/offline.
 */
export async function discoverSubdomainsForOrigins(
  origins: readonly string[],
  options: SubdomainDiscoveryOptions = {},
): Promise<SubdomainDiscoveryResult> {
  const fetchFn = options.fetchImpl ?? fetch
  const ctTimeoutMs = Math.max(500, Math.min(options.ctTimeoutMs ?? DEFAULT_CT_TIMEOUT_MS, 30_000))
  const certspotterTimeoutMs = Math.max(500, Math.min(options.certspotterTimeoutMs ?? DEFAULT_CERTSPOTTER_TIMEOUT_MS, 20_000))
  const hackerTargetTimeoutMs = Math.max(500, Math.min(options.hackerTargetTimeoutMs ?? DEFAULT_HACKERTARGET_TIMEOUT_MS, 20_000))
  const retryDelayMs = Math.max(0, Math.min(options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS, 3_000))
  const dnsTimeoutMs = Math.max(200, Math.min(options.dnsTimeoutMs ?? DEFAULT_DNS_TIMEOUT_MS, 10_000))
  const dnsConcurrency = Math.max(1, Math.min(options.dnsConcurrency ?? DEFAULT_DNS_CONCURRENCY, 24))
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
    return { discovered: [], queriedApexes: [], skippedOrigins, warnings: [], wildcardApexes: [] }
  }

  const queriedApexes = [...apexToParent.keys()]
  const warnings: string[] = []
  const wildcardApexes: string[] = []
  const discovered: DiscoveredSubdomain[] = []
  const seenOrigins = new Set<string>(origins)

  for (const apex of queriedApexes) {
    if (options.signal?.aborted) break
    const parentOrigin = apexToParent.get(apex)!
    const apexErrors: string[] = []
    const dnsInFlight = new Map<string, Promise<DnsLookupResult>>()
    const resolvedDns = new Map<string, DnsLookupResult>()
    const sourcesByHost = new Map<string, Set<SubdomainDiscoverySource>>()

    const probeLabel = (options.wildcardProbeLabel ?? `kovo-nx-${randomBytes(6).toString('hex')}`)
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, '') || `kovo-nx-${randomBytes(6).toString('hex')}`
    const probeHost = `${probeLabel}.${apex}`

    const recordSource = (hostname: string, source: SubdomainDiscoverySource) => {
      if (hostname === probeHost || excludedHosts.has(hostname)) return
      let set = sourcesByHost.get(hostname)
      if (!set) {
        set = new Set<SubdomainDiscoverySource>()
        sourcesByHost.set(hostname, set)
      }
      set.add(source)
    }

    const resolveHostCached = (hostname: string): Promise<DnsLookupResult> => {
      const existing = dnsInFlight.get(hostname)
      if (existing) return existing
      const pending = (async (): Promise<DnsLookupResult> => {
        if (options.signal?.aborted) return { cnames: [], addresses: [] }
        try {
          const raw = await withTimeout(
            dnsResolver(hostname, options.signal),
            dnsTimeoutMs,
            { cnames: [], addresses: [] },
          )
          const normalized: DnsLookupResult = {
            cnames: (raw.cnames ?? []).map(normalizeHostname).filter(Boolean),
            addresses: (raw.addresses ?? []).filter(Boolean),
          }
          resolvedDns.set(hostname, normalized)
          return normalized
        } catch {
          const empty: DnsLookupResult = { cnames: [], addresses: [] }
          resolvedDns.set(hostname, empty)
          return empty
        }
      })()
      dnsInFlight.set(hostname, pending)
      return pending
    }

    const resolveSourceCandidates = async (hosts: readonly string[], source: SubdomainDiscoverySource) => {
      if (hosts.length === 0) return
      for (const host of hosts) recordSource(host, source)
      await mapWithConcurrency(hosts, dnsConcurrency, async hostname => {
        if (options.signal?.aborted) return
        await resolveHostCached(hostname)
      })
    }

    // 1. Wildcard DNS check + common-prefix sweep (runs concurrently with passive HTTP CT sources)
    const wildcardSweepTask = (async () => {
      if (options.signal?.aborted) return
      let isWildcard = false
      try {
        const probe = await withTimeout(
          dnsResolver(probeHost, options.signal),
          dnsTimeoutMs,
          { cnames: [], addresses: [] },
        )
        const probeCnames = (probe.cnames ?? []).map(normalizeHostname).filter(Boolean)
        const probeAddrs = (probe.addresses ?? []).filter(Boolean)
        isWildcard = probeCnames.length > 0 || probeAddrs.length > 0
      } catch {
        isWildcard = false
      }
      if (isWildcard) {
        wildcardApexes.push(apex)
        return
      }
      const sweepHosts = COMMON_SUBDOMAIN_PREFIXES
        .map(prefix => `${prefix}.${apex}`)
        .filter(host => !excludedHosts.has(host) && VALID_HOSTNAME_RE.test(host))
      await mapWithConcurrency(sweepHosts, dnsConcurrency, async hostname => {
        if (options.signal?.aborted) return
        const res = await resolveHostCached(hostname)
        if (res.cnames.length > 0 || res.addresses.length > 0) {
          recordSource(hostname, 'dns_sweep')
        }
      })
    })()

    // 2. Primary passive CT source: crt.sh (15s timeout, 1 fast retry on 429/502/503/504)
    const crtTask = (async () => {
      if (options.signal?.aborted) return
      const url = `https://crt.sh/?q=%25.${encodeURIComponent(apex)}&output=json`
      const startedAt = Date.now()
      try {
        let res = await fetchFn(url, {
          method: 'GET',
          headers: {
            Accept: 'application/json',
            'User-Agent': DISCOVERY_USER_AGENT,
          },
          signal: combineSignals(options.signal, ctTimeoutMs),
        })
        if (CRT_RETRYABLE_STATUSES.has(res.status) && !options.signal?.aborted) {
          await res.body?.cancel().catch(() => undefined)
          await sleepAbortable(retryDelayMs, options.signal)
          const remainingMs = ctTimeoutMs - (Date.now() - startedAt)
          if (!options.signal?.aborted && remainingMs > 250) {
            res = await fetchFn(url, {
              method: 'GET',
              headers: {
                Accept: 'application/json',
                'User-Agent': DISCOVERY_USER_AGENT,
              },
              signal: combineSignals(options.signal, remainingMs),
            })
          }
        }
        if (!res.ok) {
          apexErrors.push(`crt.sh returned HTTP ${res.status}`)
          return
        }
        const parsed = await res.json().catch(() => null)
        if (!Array.isArray(parsed)) {
          apexErrors.push('crt.sh returned non-array payload')
          return
        }
        const ctHosts = rankAndCapCandidates(
          collectCtHosts(parsed as Array<{ name_value?: unknown; common_name?: unknown }>, apex, excludedHosts),
          apex,
          maxCandidates,
        )
        await resolveSourceCandidates(ctHosts, 'crt.sh')
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'CT lookup failed'
        apexErrors.push(`crt.sh lookup failed: ${msg.slice(0, 120)}`)
      }
    })()

    // 3. Backup passive CT source: Certspotter public issuances API (10s timeout)
    const certspotterTask = (async () => {
      if (options.signal?.aborted) return
      const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(apex)}&include_subdomains=true&expand=dns_names`
      try {
        const res = await fetchFn(url, {
          method: 'GET',
          headers: {
            Accept: 'application/json',
            'User-Agent': DISCOVERY_USER_AGENT,
          },
          signal: combineSignals(options.signal, certspotterTimeoutMs),
        })
        if (!res.ok) {
          apexErrors.push(`certspotter returned HTTP ${res.status}`)
          return
        }
        const parsed = await res.json().catch(() => null)
        if (!Array.isArray(parsed)) {
          apexErrors.push('certspotter returned non-array payload')
          return
        }
        const hosts = extractCertspotterCandidates(
          parsed as Array<{ dns_names?: unknown }>,
          apex,
          excludedHosts,
          maxCandidates,
        )
        await resolveSourceCandidates(hosts, 'certspotter')
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Certspotter lookup failed'
        apexErrors.push(`certspotter lookup failed: ${msg.slice(0, 120)}`)
      }
    })()

    // 4. Backup passive source: HackerTarget hostsearch API (8s timeout)
    const hackerTargetTask = (async () => {
      if (options.signal?.aborted) return
      const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(apex)}`
      try {
        const res = await fetchFn(url, {
          method: 'GET',
          headers: {
            Accept: 'text/plain',
            'User-Agent': DISCOVERY_USER_AGENT,
          },
          signal: combineSignals(options.signal, hackerTargetTimeoutMs),
        })
        if (!res.ok) {
          apexErrors.push(`hackertarget returned HTTP ${res.status}`)
          return
        }
        const text = await res.text().catch(() => '')
        const { hosts, rateLimitedOrError } = extractHackerTargetCandidates(text, apex, excludedHosts, maxCandidates)
        if (rateLimitedOrError) {
          apexErrors.push(`hackertarget unavailable (${rateLimitedOrError})`)
          return
        }
        await resolveSourceCandidates(hosts, 'hackertarget')
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'HackerTarget lookup failed'
        apexErrors.push(`hackertarget lookup failed: ${msg.slice(0, 120)}`)
      }
    })()

    await Promise.all([wildcardSweepTask, crtTask, certspotterTask, hackerTargetTask])

    if (apexErrors.length > 0) {
      warnings.push(`Passive subdomain discovery issues for ${apex}: ${apexErrors.join('; ')}.`)
    }

    // Union & dedupe all live resolved subdomains across every source
    const liveHosts: string[] = []
    for (const hostname of sourcesByHost.keys()) {
      const dns = resolvedDns.get(hostname)
      if (!dns) continue
      if (dns.cnames.length === 0 && dns.addresses.length === 0) continue
      liveHosts.push(hostname)
    }

    const rankedLiveHosts = rankAndCapCandidates(liveHosts, apex, maxCandidates)
    for (const hostname of rankedLiveHosts) {
      const origin = `https://${hostname}`
      if (seenOrigins.has(origin)) continue
      const dns = resolvedDns.get(hostname)
      if (!dns) continue
      const classification = classifyThirdPartyCname(dns.cnames)
      seenOrigins.add(origin)
      discovered.push({
        hostname,
        origin,
        parentOrigin,
        apexDomain: apex,
        cnames: dns.cnames,
        addresses: dns.addresses,
        thirdParty: classification.thirdParty,
        thirdPartyVendor: classification.matchedVendor,
        cnameTarget: classification.cnameTarget,
        sources: [...(sourcesByHost.get(hostname) ?? [])],
      })
    }
  }

  return { discovered, queriedApexes, skippedOrigins, warnings, wildcardApexes }
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

export interface RunDiscoverySubdomainsOptions extends SubdomainDiscoveryOptions {
  timeoutMs?: number
}

export interface RunDiscoverySubdomainsResult {
  skipped: boolean
  reason?: string
  discovery: SubdomainDiscoveryResult
  addedOrigins: string[]
  thirdPartyOrigins: string[]
  totalCandidates: number
}

/**
 * Pre-scope-review subdomain discovery for a run:
 * - Skips `local-lab`, `prepared`, non-https, localhost, and private/IP literal seeds with zero network calls.
 * - Discovers live subdomains across multi-source passive CT APIs + wildcard-safe common-prefix DNS sweep.
 * - Persists discovered hosts into `project_assets` and `run.candidates` (unapproved until scope approval)
 *   so the Scope Review screen displays all live subdomains immediately.
 */
export async function runDiscoverySubdomainsForRun(
  storage: Store,
  runId: string,
  options: RunDiscoverySubdomainsOptions = {},
): Promise<RunDiscoverySubdomainsResult> {
  const run = storage.run(runId)
  const detail = storage.projectDetail(run.projectId)
  const { project } = detail

  const emptyDiscovery: SubdomainDiscoveryResult = {
    discovered: [],
    queriedApexes: [],
    skippedOrigins: [],
    warnings: [],
    wildcardApexes: [],
  }

  if (project.environment !== 'public') {
    return {
      skipped: true,
      reason: 'non_public_environment',
      discovery: emptyDiscovery,
      addedOrigins: [],
      thirdPartyOrigins: [],
      totalCandidates: run.candidates.length,
    }
  }

  if (run.sourceMode === 'prepared') {
    return {
      skipped: true,
      reason: 'prepared_source_mode',
      discovery: emptyDiscovery,
      addedOrigins: [],
      thirdPartyOrigins: [],
      totalCandidates: run.candidates.length,
    }
  }

  const seedOrigins = [...new Set([
    ...project.seeds,
    ...detail.assets
      .filter(a => !a.thirdParty && !a.dnsSource && !a.source.startsWith('phase0_') && !a.source.startsWith('subdomain_discovery'))
      .map(a => a.origin),
  ])]

  if (!seedOrigins.some(isPublicDiscoverableOrigin)) {
    return {
      skipped: true,
      reason: 'no_public_seeds',
      discovery: {
        ...emptyDiscovery,
        skippedOrigins: seedOrigins,
      },
      addedOrigins: [],
      thirdPartyOrigins: [],
      totalCandidates: run.candidates.length,
    }
  }

  const timeoutMs = Math.max(500, Math.min(options.timeoutMs ?? DEFAULT_RUN_DISCOVERY_TIMEOUT_MS, 60_000))
  const boundedSignal = combineSignals(options.signal, timeoutMs)

  const discovery = await discoverSubdomainsForOrigins(seedOrigins, {
    ...options,
    signal: boundedSignal,
  })

  const addedOrigins: string[] = []
  const thirdPartyOrigins: string[] = []

  for (const sub of discovery.discovered) {
    const dnsSource = buildDnsSource(sub)
    const latestRun = storage.run(runId)
    const res = storage.suggestCandidateHost(latestRun, sub.origin, 'subdomain_discovery', sub.thirdParty, dnsSource)
    if (res.added) {
      addedOrigins.push(sub.origin)
      if (sub.thirdParty) thirdPartyOrigins.push(sub.origin)
    }
  }

  const finalRun = storage.run(runId)
  storage.event(
    runId,
    'discovery.subdomains_discovered',
    `Subdomain discovery checked ${discovery.queriedApexes.length} apex ${discovery.queriedApexes.length === 1 ? 'domain' : 'domains'}: ${discovery.discovered.length} live (${addedOrigins.length} newly added to scope review, ${thirdPartyOrigins.length} third-party CNAME).`,
    {
      queriedApexes: discovery.queriedApexes,
      skippedOrigins: discovery.skippedOrigins,
      wildcardApexes: discovery.wildcardApexes ?? [],
      discoveredCount: discovery.discovered.length,
      addedCount: addedOrigins.length,
      thirdPartyCount: thirdPartyOrigins.length,
      addedOrigins,
      thirdPartyOrigins,
      warnings: discovery.warnings,
    },
  )

  return {
    skipped: false,
    discovery,
    addedOrigins,
    thirdPartyOrigins,
    totalCandidates: finalRun.candidates.length,
  }
}
