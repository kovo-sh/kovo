import { randomBytes } from 'node:crypto'
import { resolve4, resolve6, resolveCname } from 'node:dns/promises'
import { isIP } from 'node:net'
import type { Candidate, DnsSource } from '../domain.ts'
import {
  icannRegistrableDomain,
  isMultiTenantPublicSuffix,
  isPublicSuffixHost,
  registrableApex,
  registrableDomain,
} from './public-suffix.ts'
import type { Run, Store } from './store.ts'

export { icannRegistrableDomain, isMultiTenantPublicSuffix, registrableApex }

export interface DnsLookupResult {
  cnames: string[]
  addresses: string[]
}

export type SubdomainDnsResolver = (hostname: string, signal?: AbortSignal) => Promise<DnsLookupResult>

export type SubdomainDiscoverySource = 'crt.sh' | 'certspotter' | 'hackertarget' | 'dns_sweep'

export interface ThirdPartyCnameClassification {
  thirdParty: boolean
  externalCname: boolean
  matchedVendor: string | null
  cnameApex: string | null
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
  /** True when the host only answered identically to the apex wildcard DNS probe. */
  wildcardOnly?: boolean
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
  /**
   * When true, allows local/private suffixes (`.local`, `.internal`, `.test`, `.home.arpa`)
   * via local DNS sweep only — external internet CT APIs are never queried for local domains.
   */
  allowLocal?: boolean
  signal?: AbortSignal
  /** Invoked incrementally as each discovery source finishes resolving live subdomains. */
  onBatch?: (hosts: DiscoveredSubdomain[]) => void
}

export interface SubdomainDiscoveryResult {
  discovered: DiscoveredSubdomain[]
  queriedApexes: string[]
  skippedOrigins: string[]
  warnings: string[]
  wildcardApexes?: string[]
}

/**
 * Managed multi-tenant SaaS vendor CNAME suffixes (help-desk, issue-tracker, SSO, CMS, status,
 * docs, commerce). Always classified as third-party on both discovered hosts and seed hosts,
 * and never widened into first-party apex discovery (`R2-H-5`).
 */
export const THIRD_PARTY_SAAS_CNAME_SUFFIXES: readonly string[] = [
  'zendesk.com',
  'freshdesk.com',
  'helpscoutdocs.com',
  'helpscout.net',
  'intercom.help',
  'statuspage.io',
  'gitbook.io',
  'readme.io',
  'notion.site',
  'webflow.io',
  'myshopify.com',
  'atlassian.net',
  'okta.com',
  'oktapreview.com',
  'auth0.com',
  'onelogin.com',
  'ghost.io',
  'squarespace.com',
  'wixsite.com',
  'hubspot.com',
  'salesforce.com',
  'force.com',
  'pagerduty.com',
  'typeform.com',
  'calendly.com',
  'greenhouse.io',
  'lever.co',
  'ashbyhq.com',
  'bamboohr.com',
  'linear.app',
  'workday.com',
  'servicenow.com',
]

const MULTI_TENANT_SAAS_SUFFIXES: ReadonlySet<string> = new Set([
  ...THIRD_PARTY_SAAS_CNAME_SUFFIXES,
  'intercom.io',
  'jira.com',
  'duosecurity.com',
  'clerk.accounts.dev',
  'shopify.com',
  'substack.com',
  'marketo.com',
  'airtable.com',
  'coda.io',
  'retool.com',
  'bubble.io',
  'glideapps.io',
  'weebly.com',
  'wordpress.com',
  'tumblr.com',
  'medium.com',
  'blogspot.com',
  'kayako.com',
  'desk.com',
  'figma.com',
  'miro.com',
])

/**
 * Pure CDN / edge proxy and first-party PaaS hosting apexes where organizations host
 * their own first-party application code behind a custom subdomain CNAME.
 * Any OTHER external CNAME apex (known or unknown/unlisted SaaS) is automatically
 * flagged as third-party via PSL apex ownership comparison.
 */
const FIRST_PARTY_HOSTING_PROXY_APEXES: ReadonlySet<string> = new Set([
  // Pure CDN / edge / DNS traffic managers
  'cloudfront.net',
  'cloudflare.net',
  'fastly.net',
  'fastlylb.net',
  'akamai.net',
  'akamaiedge.net',
  'akamaized.net',
  'edgekey.net',
  'edgesuite.net',
  'azureedge.net',
  'azurefd.net',
  'trafficmanager.net',
  'b-cdn.net',
  // First-party PaaS / cloud compute hosting endpoints
  'vercel-dns.com',
  'vercel.app',
  'netlify.app',
  'netlify.com',
  'onrender.com',
  'fly.dev',
  'amazonaws.com',
  'azurewebsites.net',
  'azurestaticapps.net',
  'run.app',
  'appspot.com',
  'web.app',
  'firebaseapp.com',
  'herokuapp.com',
  'herokudns.com',
  'pages.dev',
  'workers.dev',
  'railway.app',
  'deno.dev',
])

const SKIPPED_LOCAL_SUFFIXES = ['.localhost', '.local', '.internal', '.test', '.invalid', '.home.arpa']
const EXPLICIT_LOCAL_SWEEP_SUFFIXES = ['.local', '.internal', '.test', '.home.arpa']
const VALID_HOSTNAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/
const PRIORITY_PREFIXES = ['www', 'api', 'app', 'auth', 'oauth', 'admin', 'billing', 'portal', 'dashboard', 'account', 'accounts', 'login', 'sso', 'staging', 'dev', 'docs', 'blog', 'status']

/**
 * Curated high-value first-party subdomain prefixes probed during wildcard-safe DNS sweeps
 * so discovery stays resilient even when every external passive CT API is rate-limited or down.
 */
export const COMMON_SUBDOMAIN_PREFIXES: readonly string[] = [
  'www', 'api', 'app', 'auth', 'oauth', 'login', 'sso', 'account', 'accounts', 'clerk',
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
const MAX_CNAME_CHAIN_DEPTH = 5
const DISCOVERY_USER_AGENT = 'Kovo/2 passive subdomain discovery'

function normalizeHostname(raw: string): string {
  return raw.trim().toLowerCase().replace(/\.+$/, '')
}

function isLocalSuffixHost(host: string): boolean {
  for (const suffix of SKIPPED_LOCAL_SUFFIXES) {
    if (host.endsWith(suffix)) return true
  }
  return false
}

function isExplicitLocalSweepHost(host: string): boolean {
  for (const suffix of EXPLICIT_LOCAL_SWEEP_SUFFIXES) {
    if (host.endsWith(suffix)) return true
  }
  return false
}

function isLocalOrNonPublicHost(hostname: string): boolean {
  const host = normalizeHostname(hostname)
  if (!host || host === 'localhost' || !host.includes('.')) return true
  if (host.startsWith('[') && host.endsWith(']')) return true
  if (isIP(host) !== 0) return true
  return isLocalSuffixHost(host)
}

function extractLocalApex(hostname: string): string | null {
  const host = normalizeHostname(hostname)
  if (!host || host === 'localhost' || !host.includes('.')) return null
  if (host.startsWith('[') && host.endsWith(']')) return null
  if (isIP(host) !== 0 || !VALID_HOSTNAME_RE.test(host)) return null
  if (!isExplicitLocalSweepHost(host)) return null
  if (host.endsWith('.home.arpa')) {
    const labels = host.split('.')
    if (labels.length < 3) return null
    return labels.slice(-3).join('.')
  }
  const labels = host.split('.')
  if (labels.length < 2) return null
  return labels.slice(-2).join('.')
}

/**
 * Returns true when `hostname` is or resides under a PSL PRIVATE multi-tenant suffix
 * (e.g. `my-app.vercel.app`, `foo.netlify.app`, `bar.github.io`, `api.fly.dev`,
 * `bucket.s3.amazonaws.com`, `d111111abcdef8.cloudfront.net`, `acme-svc.a.run.app`).
 * Backed by the vendored Public Suffix List private-section classifier.
 */
export function isMultiTenantSaasHost(hostname: string): boolean {
  const host = normalizeHostname(hostname)
  if (!host) return false
  for (const suffix of MULTI_TENANT_SAAS_SUFFIXES) {
    if (host === suffix || host.endsWith(`.${suffix}`)) return true
  }
  return false
}

export function isMultiTenantSaasOrigin(origin: string): boolean {
  try {
    return isMultiTenantSaasHost(new URL(origin).hostname)
  } catch {
    return false
  }
}

export function isSharedPaasHost(hostname: string): boolean {
  const host = normalizeHostname(hostname)
  if (!host) return false
  return isMultiTenantPublicSuffix(host)
}

export function isSharedPaasOrigin(origin: string): boolean {
  try {
    return isSharedPaasHost(new URL(origin).hostname)
  } catch {
    return false
  }
}

export function apexDomainOfHost(hostname: string): string | null {
  const host = normalizeHostname(hostname)
  if (isLocalOrNonPublicHost(host) || !VALID_HOSTNAME_RE.test(host)) return null
  if (isMultiTenantPublicSuffix(host) || isPublicSuffixHost(host) || isMultiTenantSaasHost(host)) return null
  const registrable = registrableDomain(host)
  if (
    !registrable ||
    isMultiTenantPublicSuffix(registrable) ||
    isPublicSuffixHost(registrable) ||
    isMultiTenantSaasHost(registrable)
  ) {
    return null
  }
  return registrable
}

/**
 * Compute the strict auto-admission anchor host for an approved asset origin (`R2-H-5`):
 * - Anchors at the approved asset's hostname with only a leading `www.` stripped (never
 *   widening `tenant.vendor.io` or `app.corp.example` up to the registrable apex).
 * - Refuses local/IP hosts, bare public suffixes, PSL shared PaaS suffixes, and known
 *   multi-tenant SaaS vendor domains.
 */
export function autoAdmitAnchorForOrigin(origin: string): string | null {
  let url: URL
  try {
    url = new URL(origin)
  } catch {
    return null
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
  const host = normalizeHostname(url.hostname)
  if (isLocalOrNonPublicHost(host) || !VALID_HOSTNAME_RE.test(host)) return null
  if (isSharedPaasHost(host) || isPublicSuffixHost(host) || isMultiTenantSaasHost(host)) return null
  const anchor = host.startsWith('www.') ? host.slice(4) : host
  if (!anchor || !VALID_HOSTNAME_RE.test(anchor)) return null
  if (isSharedPaasHost(anchor) || isPublicSuffixHost(anchor) || isMultiTenantSaasHost(anchor)) return null
  return anchor
}

/** Returns true strictly when `hostname` is a proper subdomain of `anchor` (`*.anchor`). */
export function matchesAutoAdmitAnchor(hostname: string, anchor: string): boolean {
  const host = normalizeHostname(hostname)
  const normAnchor = normalizeHostname(anchor)
  if (!host || !normAnchor) return false
  return host.endsWith(`.${normAnchor}`)
}

/**
 * Format a discovered subdomain origin while preserving the seed origin's scheme (`http:`
 * or `https:`) and explicit non-default port (e.g. `:8443` or `:8080`). Default ports
 * (`https:` + `443`, `http:` + `80`) are normalized away.
 */
export function formatSubdomainOrigin(hostname: string, parentOrigin: string): string {
  const normalizedHost = normalizeHostname(hostname)
  let protocol = 'https:'
  let port = ''
  try {
    const parsed = new URL(parentOrigin)
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      protocol = parsed.protocol
      const isDefaultPort =
        (parsed.protocol === 'https:' && (parsed.port === '' || parsed.port === '443'))
        || (parsed.protocol === 'http:' && (parsed.port === '' || parsed.port === '80'))
      port = isDefaultPort ? '' : parsed.port
    }
  } catch {
    // Fallback to https default
  }
  return port ? `${protocol}//${normalizedHost}:${port}` : `${protocol}//${normalizedHost}`
}

/**
 * Returns the discoverable apex domain for an HTTP or HTTPS origin (preserving explicit
 * non-default ports such as `:8443` or `:8080`), or `null` when the origin is malformed,
 * non-HTTP(S), localhost, an IP literal, a shared multi-tenant PSL private suffix, or a
 * local/internal domain (unless `options.allowLocal` is explicitly set).
 */
export function extractDiscoverableApex(
  origin: string,
  options: { allowLocal?: boolean } = {},
): string | null {
  let url: URL
  try {
    url = new URL(origin)
  } catch {
    return null
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
  const publicApex = apexDomainOfHost(url.hostname)
  if (publicApex) return publicApex
  if (options.allowLocal) {
    return extractLocalApex(url.hostname)
  }
  return null
}

export function isPublicDiscoverableOrigin(origin: string): boolean {
  return extractDiscoverableApex(origin) !== null
}

function isFirstPartyHostingProxy(cnameHost: string, cnameIcannApex: string | null): boolean {
  if (cnameIcannApex && FIRST_PARTY_HOSTING_PROXY_APEXES.has(cnameIcannApex)) return true
  const pslReg = registrableDomain(cnameHost)
  if (pslReg && FIRST_PARTY_HOSTING_PROXY_APEXES.has(pslReg)) return true
  return false
}

/**
 * Universal CNAME Apex Ownership Check:
 * Walks the resolved CNAME chain and compares each CNAME target's PSL registrable apex
 * against `targetHost`'s PSL registrable apex. Whenever a CNAME points to a different
 * apex (outside pure CDN / edge / first-party PaaS hosting proxies), it is automatically
 * classified as external/third-party (`thirdParty: true`, `externalCname: true`) with
 * `matchedVendor` and `cnameApex` set to the resolved external apex — with zero hardcoded
 * SaaS vendor blocklist required.
 */
export function classifyThirdPartyCname(
  cnames: readonly string[],
  targetHost?: string,
): ThirdPartyCnameClassification {
  const normalizedTarget = targetHost ? normalizeHostname(targetHost) : ''
  const targetPslApex = normalizedTarget ? registrableDomain(normalizedTarget) : null
  const targetIcannApex = normalizedTarget ? icannRegistrableDomain(normalizedTarget) : null

  let firstCname: string | null = null
  let firstCnameApex: string | null = null

  for (const raw of cnames) {
    const target = normalizeHostname(raw)
    if (!target) continue
    const cnamePslApex = registrableDomain(target)
    const cnameIcannApex = icannRegistrableDomain(target)
    const effectiveApex = cnameIcannApex ?? cnamePslApex ?? target
    if (firstCname === null) {
      firstCname = target
      firstCnameApex = effectiveApex
    }

    const matchedKnownSaas = [...MULTI_TENANT_SAAS_SUFFIXES].find(
      suffix => target === suffix || target.endsWith(`.${suffix}`),
    )
    if (matchedKnownSaas) {
      return {
        thirdParty: true,
        externalCname: true,
        matchedVendor: matchedKnownSaas,
        cnameApex: effectiveApex,
        cnameTarget: target,
      }
    }

    // Same-apex CNAME hop (e.g. `api.acme.co.uk -> lb.acme.co.uk`) stays first-party.
    if (
      normalizedTarget
      && (
        target === normalizedTarget
        || (targetPslApex !== null && cnamePslApex !== null && cnamePslApex === targetPslApex)
        || (targetIcannApex !== null && cnameIcannApex !== null && cnameIcannApex === targetIcannApex)
      )
    ) {
      continue
    }

    // Pure CDN / edge / first-party PaaS hosting proxy stays first-party.
    if (isFirstPartyHostingProxy(target, cnameIcannApex)) {
      continue
    }

    // External CNAME apex mismatch -> classify as third-party with the resolved apex.
    return {
      thirdParty: true,
      externalCname: true,
      matchedVendor: effectiveApex,
      cnameApex: effectiveApex,
      cnameTarget: target,
    }
  }

  return {
    thirdParty: false,
    externalCname: false,
    matchedVendor: null,
    cnameApex: firstCnameApex,
    cnameTarget: firstCname,
  }
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

function sprawlPatternKey(prefix: string): string | null {
  const labels = prefix.split('.')
  let changed = false
  const generalized = labels.map(label => {
    if (/^pr-\d+$/.test(label)) { changed = true; return 'pr-*' }
    if (/^deploy-preview-\d+$/.test(label)) { changed = true; return 'deploy-preview-*' }
    if (/^preview-\d+$/.test(label)) { changed = true; return 'preview-*' }
    const numShard = /^([a-z0-9-]+)-\d{3,}$/.exec(label)
    if (numShard) { changed = true; return `${numShard[1]}-*` }
    const hexDeploy = /^([a-z0-9-]+)-([0-9a-f]{7,})$/.exec(label)
    if (hexDeploy && /\d/.test(hexDeploy[2])) { changed = true; return `${hexDeploy[1]}-*` }
    return label
  })
  return changed ? generalized.join('.') : null
}

/**
 * Collapse repetitive generated preview/shard subdomains (`pr-\d+.*`, `deploy-preview-\d+.*`,
 * `preview-\d+.*`, `[a-z0-9-]+-\d{3,}.*`, hex deploy hashes) to at most 1 representative per
 * pattern so noisy preview deploys never crowd out high-signal first-party hosts.
 */
export function collapseSprawlCandidates(hosts: readonly string[], normalizedApex: string): string[] {
  const suffix = `.${normalizedApex}`
  const seenPatterns = new Set<string>()
  const out: string[] = []
  for (const host of hosts) {
    if (!host.endsWith(suffix)) {
      out.push(host)
      continue
    }
    const prefix = host.slice(0, -suffix.length)
    const key = sprawlPatternKey(prefix)
    if (!key) {
      out.push(host)
      continue
    }
    if (seenPatterns.has(key)) continue
    seenPatterns.add(key)
    out.push(host)
  }
  return out
}

function rankAndCapCandidates(
  hosts: Iterable<string>,
  normalizedApex: string,
  maxCandidates: number,
  options: { collapseSprawl?: boolean } = {},
): string[] {
  const deduped = [...new Set(hosts)]
  deduped.sort((a, b) => {
    const [ar0, ar1, ar2] = candidateRank(a, normalizedApex)
    const [br0, br1, br2] = candidateRank(b, normalizedApex)
    if (ar0 !== br0) return ar0 - br0
    if (ar1 !== br1) return ar1 - br1
    return ar2.localeCompare(br2)
  })
  const filtered = options.collapseSprawl === false
    ? deduped
    : collapseSprawlCandidates(deduped, normalizedApex)
  return filtered.slice(0, Math.max(1, Math.min(Math.floor(maxCandidates), 200)))
}

export interface ScopeRankableAsset {
  id?: string
  origin: string
  source?: string
  thirdParty?: boolean
  includeSubdomains?: boolean
  dnsSource?: unknown
}

export interface ScopeRankingOptions {
  maxAssets?: number
  includeThirdParty?: boolean
  includeBulkDns?: boolean
}

export interface RankedScopeAsset<T extends ScopeRankableAsset = ScopeRankableAsset> {
  asset: T
  score: number
  apex: string | null
  sameApexAsSeed: boolean
  depth: number
  noisy: boolean
}

const SCOPE_HIGH_VALUE_TIER1: ReadonlySet<string> = new Set([
  'api', 'app', 'auth', 'admin', 'billing', 'oauth', 'sso', 'login', 'portal',
  'dashboard', 'console', 'graphql', 'gateway', 'accounts', 'account',
])

const SCOPE_HIGH_VALUE_TIER2: ReadonlySet<string> = new Set([
  'www', 'pay', 'payments', 'checkout', 'mcp', 'cloud', 'engine', 'internal',
  'staging', 'stage', 'dev', 'beta', 'sandbox', 'studio', 'web', 'my', 'id',
  'identity', 'token', 'webhooks', 'webhook', 'docs', 'blog', 'status',
])

function extractOriginHostname(origin: string): string {
  try {
    return normalizeHostname(new URL(origin).hostname)
  } catch {
    return normalizeHostname(origin.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, ''))
  }
}

function canonicalOriginKey(origin: string): string {
  try {
    return new URL(origin).origin.toLowerCase()
  } catch {
    return origin.trim().toLowerCase().replace(/\/+$/, '')
  }
}

function isDiscoveredSubdomainSource(source?: string): boolean {
  return (
    source === 'subdomain_discovery'
    || source === 'phase0_ct_discovery'
    || source === 'phase0_subdomain_discovery'
  )
}

/**
 * Canonical PSL-backed scope ranking helper for Scope Review (`consent.tsx`) and
 * server-side asset prioritization:
 * - Resolves registrable apex via PSL (correctly handling `.co.uk`, `.com.au`,
 *   multi-part ccTLDs, nested subdomains, and non-443 origins).
 * - Refuses to collapse shared multi-tenant PSL private suffixes (`*.vercel.app`,
 *   `*.github.io`, etc.) across unrelated tenants.
 * - Computes subdomain depth relative to the PSL registrable apex so multi-part
 *   ccTLDs (`api.acme.co.uk`) are never penalized relative to `.com` domains.
 * - Ranks seeds > repo/spec > exact apex > Tier-1 prefixes > Tier-2 prefixes >
 *   standard subdomains > noisy preview sprawl > foreign apex / third-party CNAMEs.
 */
export function rankScopeAssets<T extends ScopeRankableAsset>(
  assets: readonly T[],
  seedOrigins: readonly string[],
  options: ScopeRankingOptions = {},
): RankedScopeAsset<T>[] {
  const seedOriginSet = new Set(seedOrigins.map(canonicalOriginKey))
  const seedHostSet = new Set(seedOrigins.map(extractOriginHostname).filter(Boolean))
  const seedApexes = new Set<string>()
  for (const seed of seedOrigins) {
    const seedHost = extractOriginHostname(seed)
    if (!seedHost || isMultiTenantPublicSuffix(seedHost)) continue
    const apex = registrableApex(seed)
    if (apex && !isMultiTenantPublicSuffix(apex)) {
      seedApexes.add(apex)
    }
  }

  const ranked: Array<RankedScopeAsset<T> & { _idx: number; _hostLen: number }> = []

  for (let idx = 0; idx < assets.length; idx += 1) {
    const asset = assets[idx]!
    if (options.includeThirdParty === false && asset.thirdParty) continue
    const isBulkDns = Boolean(asset.dnsSource) && !isDiscoveredSubdomainSource(asset.source)
    if (options.includeBulkDns === false && isBulkDns) continue

    const host = extractOriginHostname(asset.origin)
    const apex = registrableApex(asset.origin)
    const originKey = canonicalOriginKey(asset.origin)
    const isExactSeed = seedOriginSet.has(originKey) || (seedHostSet.has(host) && !isDiscoveredSubdomainSource(asset.source))
    const isSharedTenant = host ? isMultiTenantPublicSuffix(host) : false
    const sameApexAsSeed = isExactSeed || (
      !isSharedTenant && apex !== null && seedApexes.has(apex)
    )

    let relativePrefix = ''
    let depth = 0
    if (apex && host === apex) {
      depth = 0
    } else if (apex && host.endsWith(`.${apex}`)) {
      relativePrefix = host.slice(0, -(apex.length + 1))
      depth = relativePrefix.split('.').filter(Boolean).length
    } else if (host) {
      const parts = host.split('.').filter(Boolean)
      depth = Math.max(0, parts.length - 2)
      relativePrefix = depth > 0 ? parts.slice(0, depth).join('.') : ''
    }

    const firstLabel = relativePrefix ? (relativePrefix.split('.')[0] ?? '') : ''
    const noisy = relativePrefix ? sprawlPatternKey(relativePrefix) !== null : false

    const src = (asset.source ?? '').toLowerCase()
    let score: number
    if (isExactSeed || src === 'project seed' || (!asset.dnsSource && !isDiscoveredSubdomainSource(asset.source) && src === '')) {
      score = 1000
    } else if (/repo|spec|openapi|swagger|github|graphql/.test(src)) {
      score = 850
    } else if (depth === 0 && sameApexAsSeed) {
      score = 760
    } else if (noisy) {
      score = 50
    } else if (SCOPE_HIGH_VALUE_TIER1.has(firstLabel)) {
      score = Math.max(300, 700 - Math.max(0, depth - 1) * 40)
    } else if (SCOPE_HIGH_VALUE_TIER2.has(firstLabel)) {
      score = Math.max(200, 550 - Math.max(0, depth - 1) * 40)
    } else {
      score = Math.max(100, 440 - depth * 40)
    }

    if (seedOrigins.length > 0 && !sameApexAsSeed) {
      score -= 200
    }
    if (asset.thirdParty) {
      score -= 500
    }

    ranked.push({
      asset,
      score,
      apex,
      sameApexAsSeed,
      depth,
      noisy,
      _idx: idx,
      _hostLen: host.length,
    })
  }

  ranked.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score
    if (a.depth !== b.depth) return a.depth - b.depth
    if (a._hostLen !== b._hostLen) return a._hostLen - b._hostLen
    const cmp = a.asset.origin.localeCompare(b.asset.origin)
    return cmp !== 0 ? cmp : a._idx - b._idx
  })

  const limited = options.maxAssets !== undefined
    ? ranked.slice(0, Math.max(0, Math.floor(options.maxAssets)))
    : ranked

  return limited.map(({ asset, score, apex, sameApexAsSeed, depth, noisy }) => ({
    asset,
    score,
    apex,
    sameApexAsSeed,
    depth,
    noisy,
  }))
}

/** Alias for `rankScopeAssets` for discoverability by UI and planner callers. */
export const rankDiscoveredAssets = rankScopeAssets

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

  return rankAndCapCandidates(found, normalizedApex, maxCandidates, { collapseSprawl: false })
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

async function resolveCnameChain(
  hostname: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<string[]> {
  const chain: string[] = []
  const visited = new Set<string>([normalizeHostname(hostname)])
  let current = normalizeHostname(hostname)
  for (let depth = 0; depth < MAX_CNAME_CHAIN_DEPTH; depth += 1) {
    if (signal?.aborted) break
    const hops = await withTimeout(
      resolveCname(current).catch(() => [] as string[]),
      timeoutMs,
      [] as string[],
    )
    const next = hops.map(normalizeHostname).find(h => h && !visited.has(h))
    if (!next) break
    visited.add(next)
    chain.push(next)
    current = next
  }
  return chain
}

export async function defaultSubdomainDnsResolver(
  hostname: string,
  signal?: AbortSignal,
  timeoutMs = DEFAULT_DNS_TIMEOUT_MS,
): Promise<DnsLookupResult> {
  if (signal?.aborted) return { cnames: [], addresses: [] }
  const [cnames, ipv4, ipv6] = await Promise.all([
    resolveCnameChain(hostname, timeoutMs, signal),
    withTimeout(resolve4(hostname).catch(() => [] as string[]), timeoutMs, [] as string[]),
    withTimeout(resolve6(hostname).catch(() => [] as string[]), timeoutMs, [] as string[]),
  ])
  return {
    cnames: cnames.filter(Boolean),
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
 * Multi-source resilient passive + wildcard-safe DNS subdomain discovery:
 * - `crt.sh` (15s timeout, 1 fast retry on 429/502/503/504)
 * - Certspotter public issuances API (10s timeout)
 * - HackerTarget hostsearch API (8s timeout)
 * - Wildcard-safe common-prefix DNS sweep (~60 high-value prefixes, skipped if random label resolves)
 * Preserves the seed origin's scheme (`http:` / `https:`) and explicit non-default ports
 * (e.g. `:8443`, `:8080`). Skips localhost, IP literals, and PSL private multi-tenant PaaS
 * suffixes with zero network calls; local/internal suffixes run DNS sweep only when
 * `options.allowLocal` is enabled (never leaking internal names to public CT APIs).
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
  const allowLocal = Boolean(options.allowLocal)
  const dnsResolver: SubdomainDnsResolver = options.dnsResolver
    ?? ((host, sig) => defaultSubdomainDnsResolver(host, sig, dnsTimeoutMs))

  const skippedOrigins: string[] = []
  const excludedHosts = new Set<string>()
  const apexToParent = new Map<string, string>()

  for (const origin of origins) {
    let seedHost: string
    try {
      const parsed = new URL(origin)
      seedHost = normalizeHostname(parsed.hostname)
      excludedHosts.add(seedHost)
    } catch {
      skippedOrigins.push(origin)
      continue
    }
    if (isSharedPaasHost(seedHost) || isMultiTenantSaasHost(seedHost)) {
      skippedOrigins.push(origin)
      continue
    }
    const apex = extractDiscoverableApex(origin, { allowLocal })
    if (!apex) {
      skippedOrigins.push(origin)
      continue
    }
    // R2-H-5: Check third-party CNAME ownership on subdomain seeds before using them as discovery anchors.
    if (seedHost !== apex) {
      try {
        const seedDns = await withTimeout(
          dnsResolver(seedHost, options.signal),
          dnsTimeoutMs,
          { cnames: [], addresses: [] },
        )
        const seedCnames = (seedDns.cnames ?? []).map(normalizeHostname).filter(Boolean)
        if (classifyThirdPartyCname(seedCnames, seedHost).thirdParty) {
          skippedOrigins.push(origin)
          continue
        }
      } catch {
        // Best-effort DNS check for seed CNAME ownership
      }
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
  const seenOrigins = new Set<string>(origins.map(canonicalOriginKey))

  for (const apex of queriedApexes) {
    if (options.signal?.aborted) break
    const parentOrigin = apexToParent.get(apex)!
    const isLocalApex = isLocalSuffixHost(apex)
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

    const discoveredByOrigin = new Map<string, DiscoveredSubdomain>()
    let apexEmittedCount = 0
    let wildcardProbeSignature: { cnamesKey: string; addressesKey: string } | null = null

    const isWildcardEquivalentDns = (dns: DnsLookupResult): boolean => {
      if (!wildcardProbeSignature) return false
      const cnamesKey = [...dns.cnames].sort().join(',')
      const addressesKey = [...dns.addresses].sort().join(',')
      return cnamesKey === wildcardProbeSignature.cnamesKey && addressesKey === wildcardProbeSignature.addressesKey
    }

    const emitLiveBatch = (hosts: readonly string[], source: SubdomainDiscoverySource) => {
      const liveForSource: string[] = []
      for (const hostname of hosts) {
        if (hostname === probeHost || excludedHosts.has(hostname)) continue
        const dns = resolvedDns.get(hostname)
        if (!dns || (dns.cnames.length === 0 && dns.addresses.length === 0)) continue
        liveForSource.push(hostname)
      }
      if (liveForSource.length === 0) return

      const rankedBatch = rankAndCapCandidates(liveForSource, apex, maxCandidates)
      const newlyEmitted: DiscoveredSubdomain[] = []
      for (const hostname of rankedBatch) {
        const origin = formatSubdomainOrigin(hostname, parentOrigin)
        const originKey = canonicalOriginKey(origin)
        const existing = discoveredByOrigin.get(origin)
        if (existing) {
          if (!existing.sources) existing.sources = []
          if (!existing.sources.includes(source)) existing.sources.push(source)
          continue
        }
        if (seenOrigins.has(originKey) || apexEmittedCount >= maxCandidates) continue
        const dns = resolvedDns.get(hostname)
        if (!dns) continue
        const classification = classifyThirdPartyCname(dns.cnames, hostname)
        const wildcardOnly = isWildcardEquivalentDns(dns)
        const entry: DiscoveredSubdomain = {
          hostname,
          origin,
          parentOrigin,
          apexDomain: apex,
          cnames: dns.cnames,
          addresses: dns.addresses,
          thirdParty: classification.thirdParty,
          thirdPartyVendor: classification.matchedVendor,
          cnameTarget: classification.cnameTarget,
          ...(wildcardOnly ? { wildcardOnly: true } : {}),
          sources: [...(sourcesByHost.get(hostname) ?? [source])],
        }
        if (!entry.sources!.includes(source)) entry.sources!.push(source)
        seenOrigins.add(originKey)
        discoveredByOrigin.set(origin, entry)
        discovered.push(entry)
        apexEmittedCount += 1
        newlyEmitted.push(entry)
      }

      if (newlyEmitted.length > 0 && options.onBatch) {
        try {
          options.onBatch(newlyEmitted)
        } catch {
          // Incremental batch consumer errors must never disrupt discovery
        }
      }
    }

    const resolveSourceCandidates = async (hosts: readonly string[], source: SubdomainDiscoverySource) => {
      if (hosts.length === 0) return
      for (const host of hosts) recordSource(host, source)
      await mapWithConcurrency(hosts, dnsConcurrency, async hostname => {
        if (options.signal?.aborted) return
        await resolveHostCached(hostname)
      })
      emitLiveBatch(hosts, source)
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
        if (isWildcard) {
          wildcardProbeSignature = {
            cnamesKey: [...probeCnames].sort().join(','),
            addressesKey: [...probeAddrs].sort().join(','),
          }
        }
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
      const resolvedSweepHosts: string[] = []
      await mapWithConcurrency(sweepHosts, dnsConcurrency, async hostname => {
        if (options.signal?.aborted) return
        const res = await resolveHostCached(hostname)
        if (res.cnames.length > 0 || res.addresses.length > 0) {
          recordSource(hostname, 'dns_sweep')
          resolvedSweepHosts.push(hostname)
        }
      })
      emitLiveBatch(resolvedSweepHosts, 'dns_sweep')
    })()

    // 2. Primary passive CT source: crt.sh (skipped for local/internal apexes)
    const crtTask = isLocalApex ? Promise.resolve() : (async () => {
      if (options.signal?.aborted) return
      const url = `https://crt.sh/?q=%25.${encodeURIComponent(apex)}&output=json&exclude=expired&deduplicate=Y`
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

    // 3. Backup passive CT source: Certspotter public issuances API (skipped for local/internal apexes)
    const certspotterTask = isLocalApex ? Promise.resolve() : (async () => {
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

    // 4. Backup passive source: HackerTarget hostsearch API (skipped for local/internal apexes)
    const hackerTargetTask = isLocalApex ? Promise.resolve() : (async () => {
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

    // Reconcile sources and ensure any remaining resolved hosts (within maxCandidates) are included
    const liveHosts: string[] = []
    for (const hostname of sourcesByHost.keys()) {
      const dns = resolvedDns.get(hostname)
      if (!dns) continue
      if (dns.cnames.length === 0 && dns.addresses.length === 0) continue
      liveHosts.push(hostname)
    }

    const rankedLiveHosts = rankAndCapCandidates(liveHosts, apex, maxCandidates)
    const remainingBatch: DiscoveredSubdomain[] = []
    for (const hostname of rankedLiveHosts) {
      const origin = formatSubdomainOrigin(hostname, parentOrigin)
      const originKey = canonicalOriginKey(origin)
      const existing = discoveredByOrigin.get(origin)
      if (existing) {
        existing.sources = [...(sourcesByHost.get(hostname) ?? existing.sources ?? [])]
        continue
      }
      if (seenOrigins.has(originKey) || apexEmittedCount >= maxCandidates) continue
      const dns = resolvedDns.get(hostname)
      if (!dns) continue
      const classification = classifyThirdPartyCname(dns.cnames, hostname)
      const wildcardOnly = isWildcardEquivalentDns(dns)
      seenOrigins.add(originKey)
      const entry: DiscoveredSubdomain = {
        hostname,
        origin,
        parentOrigin,
        apexDomain: apex,
        cnames: dns.cnames,
        addresses: dns.addresses,
        thirdParty: classification.thirdParty,
        thirdPartyVendor: classification.matchedVendor,
        cnameTarget: classification.cnameTarget,
        ...(wildcardOnly ? { wildcardOnly: true } : {}),
        sources: [...(sourcesByHost.get(hostname) ?? [])],
      }
      discoveredByOrigin.set(origin, entry)
      discovered.push(entry)
      apexEmittedCount += 1
      remainingBatch.push(entry)
    }
    if (remainingBatch.length > 0 && options.onBatch) {
      try {
        options.onBatch(remainingBatch)
      } catch {
        // Ignore consumer errors
      }
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
 * Apply Phase-0 discovered subdomains to a run (`R2-H-5`):
 * - Anchors auto-admission strictly at each approved non-third-party first-party asset's host
 *   (stripping only a leading `www.`), admitting ONLY `*.anchor` — never widening to a shared
 *   PaaS/SaaS vendor apex.
 * - Never auto-admits origins declined by the operator in scope review (`runs.declined_origins`),
 *   nor hosts that only answered because of wildcard DNS (`wildcardOnly` or `wildcardApexes`).
 * - Routes all dynamic admissions through `storage.runsRepo.admitDynamicOrigin`, which bumps
 *   `scopeRevision` and emits `asset.auto_admitted`.
 */
export function applyDiscoveredSubdomainsToRun(
  storage: Store,
  runId: string,
  result: SubdomainDiscoveryResult,
  approvedOrigins: Set<string>,
): AppliedSubdomainDiscovery {
  const run = storage.run(runId)
  const detail = storage.projectDetail(run.projectId)
  const allowedAnchors = new Set<string>()
  const approvedAnchorAssets = [
    ...detail.assets,
    ...run.candidates.filter(c => !detail.assets.some(a => a.origin === c.origin)),
  ]
  for (const asset of approvedAnchorAssets) {
    if (!asset.includeSubdomains || asset.thirdParty) continue
    if (!approvedOrigins.has(asset.origin)) continue
    if (isSharedPaasOrigin(asset.origin) || isMultiTenantSaasOrigin(asset.origin)) continue
    if (asset.dnsSource?.externalAliases?.length) continue
    const anchor = autoAdmitAnchorForOrigin(asset.origin)
    if (anchor) {
      allowedAnchors.add(anchor)
    }
  }
  const wildcardApexSet = new Set((result.wildcardApexes ?? []).map(normalizeHostname).filter(Boolean))

  const admitted: Candidate[] = []
  const candidatesOnly: Candidate[] = []
  const thirdParty: Candidate[] = []
  const admittedOrigins: string[] = []
  const candidateOrigins: string[] = []
  const thirdPartyOrigins: string[] = []

  for (const sub of result.discovered) {
    if (approvedOrigins.has(sub.origin)) continue
    // Defense-in-depth: PSL private multi-tenant hosts, known multi-tenant SaaS vendors, and bare
    // public suffixes must never auto-admit sibling tenants even from synthetic discovery entries.
    const subHost = normalizeHostname(sub.hostname)
    const subApex = apexDomainOfHost(sub.hostname)
    const isSharedOrUnsafeTenant =
      isSharedPaasHost(sub.hostname) ||
      isSharedPaasOrigin(sub.origin) ||
      isSharedPaasHost(sub.apexDomain) ||
      isSharedPaasOrigin(sub.parentOrigin) ||
      isMultiTenantSaasHost(sub.hostname) ||
      isMultiTenantSaasOrigin(sub.origin) ||
      isMultiTenantSaasHost(sub.apexDomain) ||
      isMultiTenantSaasOrigin(sub.parentOrigin) ||
      isPublicSuffixHost(sub.apexDomain)
    if (isSharedOrUnsafeTenant) continue

    const dnsSource = buildDnsSource(sub)
    const isWildcardHost =
      Boolean(sub.wildcardOnly) ||
      (subApex !== null && wildcardApexSet.has(subApex)) ||
      wildcardApexSet.has(normalizeHostname(sub.apexDomain))
    const matchedAnchor = [...allowedAnchors].find(anchor => matchesAutoAdmitAnchor(subHost, anchor)) ?? null
    const isDeclined = storage.runsRepo.isOriginDeclined(runId, sub.origin)
    const shouldAutoAdmit =
      !sub.thirdParty &&
      !isWildcardHost &&
      !isDeclined &&
      matchedAnchor !== null &&
      subApex !== null

    const latestRun: Run = storage.run(runId)
    storage.suggestCandidateHost(latestRun, sub.origin, 'phase0_ct_discovery', sub.thirdParty, dnsSource)
    const withCand = storage.run(runId)
    const cand = withCand.candidates.find(c => c.origin === sub.origin)
    if (!cand) continue

    if (shouldAutoAdmit) {
      const admitRes = storage.runsRepo.admitDynamicOrigin({
        runId,
        origin: sub.origin,
        source: 'phase0_ct_discovery',
        thirdParty: sub.thirdParty,
        dnsSource,
        anchor: matchedAnchor,
        reason: 'phase0_subdomain_auto_admit',
      })
      if (admitRes.admitted && admitRes.candidate) {
        approvedOrigins.add(sub.origin)
        admitted.push(admitRes.candidate)
        admittedOrigins.push(sub.origin)
      } else {
        candidatesOnly.push(cand)
        candidateOrigins.push(sub.origin)
      }
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
 * - Skips `local-lab`, `prepared`, localhost, IP literal, and PSL private PaaS seeds with zero network calls.
 * - Discovers live subdomains across multi-source passive CT APIs + wildcard-safe common-prefix DNS sweep,
 *   preserving seed scheme and explicit non-default ports.
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

  const addedOrigins: string[] = []
  const thirdPartyOrigins: string[] = []
  const persistedOrigins = new Set<string>()

  const persistBatch = (batch: DiscoveredSubdomain[], emitBatchEvent: boolean) => {
    const batchAdded: string[] = []
    for (const sub of batch) {
      if (persistedOrigins.has(sub.origin)) continue
      persistedOrigins.add(sub.origin)
      const dnsSource = buildDnsSource(sub)
      const latestRun = storage.run(runId)
      const res = storage.suggestCandidateHost(latestRun, sub.origin, 'subdomain_discovery', sub.thirdParty, dnsSource)
      if (res.added) {
        addedOrigins.push(sub.origin)
        batchAdded.push(sub.origin)
        if (sub.thirdParty) thirdPartyOrigins.push(sub.origin)
      }
    }
    if (emitBatchEvent && batchAdded.length > 0) {
      storage.event(
        runId,
        'discovery.subdomains_batch',
        `Discovered ${batchAdded.length} live ${batchAdded.length === 1 ? 'subdomain' : 'subdomains'} (${addedOrigins.length} total so far).`,
        {
          addedCount: batchAdded.length,
          totalAddedCount: addedOrigins.length,
          addedOrigins: batchAdded,
        },
      )
    }
  }

  const discovery = await discoverSubdomainsForOrigins(seedOrigins, {
    ...options,
    signal: boundedSignal,
    onBatch: batch => {
      persistBatch(batch, true)
      options.onBatch?.(batch)
    },
  })

  // Ensure any remaining entries not already persisted during streaming are recorded
  persistBatch(discovery.discovered, false)

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
