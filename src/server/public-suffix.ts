/**
 * Public Suffix List lookups for credential-scope, multi-tenant PaaS refusal,
 * CNAME apex ownership, and canonical scope ranking decisions.
 *
 * The data file (`public-suffix-list.ts`) is the vendored multi-label subset of
 * https://publicsuffix.org/list/public_suffix_list.dat. Rules may be plain
 * (`co.uk`), wildcard (`*.ck`) or exception (`!www.ck`) entries, exactly as in the
 * upstream list. Plain single-label TLDs are covered by the PSL's implicit `*`
 * default rule, so they are not stored.
 *
 * This module is intentionally dependency-free: it replaces ad-hoc hardcoded suffix
 * lists with structured PSL ICANN vs. PRIVATE section classification so shared
 * platform tenants (`github.io`, `vercel.app`, `fly.dev`, `pages.dev`,
 * `s3.amazonaws.com`, …) are isolated while ICANN multi-part ccTLDs (`co.uk`,
 * `com.au`, `com.co`) resolve accurately.
 */
import { domainToASCII } from 'node:url'
import { publicSuffixRules } from './public-suffix-list.ts'

const RULES: ReadonlySet<string> = new Set(
  publicSuffixRules
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean),
)

/**
 * Multi-label generic TLDs that have legitimate ICANN registry sub-trees in the PSL.
 * Every other >2-character non-IDN TLD multi-label entry (e.g. under `.com`, `.net`,
 * `.org`, `.app`, `.dev`, `.aws`, `.cloud`, `.run`, `.site`, `.page`) belongs to the
 * PSL PRIVATE section.
 */
const ICANN_GENERIC_MULTI_TLDS: ReadonlySet<string> = new Set([
  'aero', 'arpa', 'edu', 'gov', 'int', 'mil', 'museum', 'pro',
])

/**
 * Standard ICANN second-level registry labels under 2-letter ccTLDs (e.g. `co.uk`,
 * `com.au`, `ac.jp`, `gov.uk`, `com.co`, `edu.cn`, `net.nz`, `org.za`).
 */
const ICANN_CC_SLDS: ReadonlySet<string> = new Set([
  'co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'mil', 'int', 'sch', 'ltd', 'plc',
  'go', 'or', 'ne', 'ed', 'ad', 'gr', 'lg', 'gob', 'gouv', 'asso', 'tm', 'nom', 'name',
  'info', 'biz', 'pro', 'id', 'me', 'med', 'art', 'firm', 'store', 'web', 'rec', 'ind',
  'gen', 'cri', 'geek', 'school', 'govt', 'health', 'parliament', 'nhs', 'police', 'mod',
  'nic', 'coop', 'ngo', 'priv', 'presse', 'asn', 'conf', 'oz', 'csiro', 'iwi', 'maori', 'kiwi',
  'k12', 'lib', 'cc', 'fed', 'isa', 'nsn', 'dni', 'museum', 'law', 'eng', 'vet', 'bio', 'agr',
  'adm', 'adv', 'am', 'arq', 'ato', 'bmd', 'cim', 'cng', 'cnt', 'ecn', 'esp', 'etc', 'eti',
  'far', 'flog', 'fm', 'fnd', 'fot', 'fst', 'g12', 'ggf', 'imb', 'inf', 'jor', 'jus', 'leg',
  'lel', 'mat', 'mp', 'mus', 'not', 'ntr', 'odo', 'ppg', 'psc', 'psi', 'qsl', 'radio', 'slg',
  'srv', 'taxi', 'teo', 'tmp', 'trd', 'tur', 'tv', 'vlog', 'wiki', 'zlg', 'in', 'ai', 'sc',
  'act', 'nsw', 'nt', 'qld', 'sa', 'tas', 'vic', 'wa', 'ab', 'bc', 'mb', 'nb', 'nf', 'nl',
  'ns', 'nu', 'on', 'pe', 'qc', 'sk', 'yk', 'pp', 'spb', 'msk', 'its', 'res', 'sld', 'fin',
  'per', 'nat', 'pol', 'soc', 'sci', 'tec', 'ong', 'red', 'gub', 'city', 'pref', 'metro',
  'state', 'council', 'service', 'api', 'campaign',
])

/** Commercial ccTLD second-level registries: 3+-label PSL rules beneath them are PRIVATE. */
const COMMERCIAL_CC_SLDS: ReadonlySet<string> = new Set([
  'co', 'com', 'net', 'org', 'biz', 'info', 'web', 'me', 'nom', 'name',
])

/** ccTLDs with 2-letter geographic region/state/province ICANN SLDs (e.g. `ca.us`, `bj.cn`). */
const GEO_CCTLDS: ReadonlySet<string> = new Set([
  'jp', 'no', 'it', 'pl', 'ua', 'cn', 'us', 'ru', 'br', 'kr', 'tw', 'au', 'ca', 'in', 'za', 'nz',
  'ar', 'mx', 'cl', 'pe', 've', 'id', 'my', 'ph', 'th', 'vn', 'tr', 'il', 'sa', 'ae', 'eg', 'ng',
  'ke', 'gr', 'es', 'fr', 'de', 'nl', 'be', 'ch', 'at', 'se', 'dk', 'fi', 'ie', 'pt', 'hu', 'ro',
  'bg', 'hr', 'si', 'sk', 'cz', 'ee', 'lv', 'lt', 'by', 'kz',
])

const MUNICIPAL_CCTLDS: ReadonlySet<string> = new Set(['jp', 'no', 'it', 'pl', 'ua'])

const GOV_EDU_SLDS: ReadonlySet<string> = new Set([
  'gov', 'edu', 'ac', 'mil', 'sch', 'gob', 'gouv', 'k12', 'lg', 'city', 'pref', 'state',
])

const GOV_EDU_SUBLABELS: ReadonlySet<string> = new Set([
  'service', 'api', 'campaign', 'k12', 'lib', 'cc', 'city', 'pref',
  'nsw', 'vic', 'qld', 'wa', 'sa', 'tas', 'act', 'nt', 'gov', 'edu', 'ac',
])

/**
 * Minimal supplemental multi-tenant roots omitted at the bare 2-label level in upstream PSL
 * (PSL lists `up.railway.app` and 600+ `*.amazonaws.com` sub-rules, while `glitch.me` was
 * never submitted). Checked only by `isMultiTenantPublicSuffix` so pure PSL `registrableDomain`
 * semantics stay 100% faithful to Mozilla PSL.
 */
const SUPPLEMENTAL_MULTI_TENANT_ROOTS: readonly string[] = [
  'amazonaws.com',
  'railway.app',
  'glitch.me',
]

function isPrivatePslRule(rule: string): boolean {
  if (rule.startsWith('!')) return false
  const isWild = rule.startsWith('*.')
  const bare = isWild ? rule.slice(2) : rule
  const labels = bare.split('.')
  if (labels.length < 2) return false
  const tld = labels[labels.length - 1]!
  if (tld.length > 2 && !tld.startsWith('xn--')) {
    return !ICANN_GENERIC_MULTI_TLDS.has(tld)
  }
  if (tld.startsWith('xn--')) {
    return labels.length > 2
  }
  if (isWild) {
    const sld = labels[labels.length - 2]!
    if (ICANN_CC_SLDS.has(sld) && !COMMERCIAL_CC_SLDS.has(sld)) return false
    return true
  }
  if (labels.length === 2) {
    const sld = labels[0]!
    if (ICANN_CC_SLDS.has(sld)) return false
    if (sld.length === 2 && GEO_CCTLDS.has(tld)) return false
    if (MUNICIPAL_CCTLDS.has(tld)) return false
    return true
  }
  const sld = labels[labels.length - 2]!
  if (COMMERCIAL_CC_SLDS.has(sld)) return true
  if (GOV_EDU_SLDS.has(sld)) {
    const first = labels[0]!
    if (GOV_EDU_SUBLABELS.has(first)) return false
    if (labels.length === 3 && (sld === 'gov' || sld === 'edu' || sld === 'ac' || sld === 'mil' || sld === 'gob' || sld === 'gouv')) {
      return false
    }
  }
  if ((MUNICIPAL_CCTLDS.has(tld) || tld === 'us') && labels.length === 3 && !labels[0]!.includes('-')) {
    return false
  }
  return true
}

const PRIVATE_RULES: ReadonlySet<string> = new Set(
  [...RULES].filter(isPrivatePslRule),
)

const ICANN_RULES: ReadonlySet<string> = new Set(
  [...RULES].filter(rule => !PRIVATE_RULES.has(rule)),
)

/** Lowercase, strip a trailing dot and convert IDN labels to their ASCII form. */
export function normalizeHostname(hostname: string): string {
  const trimmed = hostname.trim().toLowerCase().replace(/\.+$/, '')
  if (!trimmed) return ''
  if (trimmed.includes(':')) return trimmed // IPv6 literal; never a DNS name
  const ascii = domainToASCII(trimmed)
  return (ascii || trimmed).toLowerCase()
}

/** IPv4/IPv6 literals are never registrable domains. */
export function isIpLiteralHost(hostname: string): boolean {
  const bare = hostname.replace(/^\[|\]$/g, '')
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(bare)) {
    return bare.split('.').every(part => Number(part) <= 255)
  }
  return bare.includes(':') && /^[0-9a-f:.]+$/i.test(bare)
}

interface SuffixMatch {
  labelCount: number
  matchedRule: string | null
  section: 'icann' | 'private'
}

/**
 * Resolve the winning PSL rule for `labels` against a given rule set, following the
 * PSL algorithm: exception rules win, otherwise the longest matching rule, otherwise
 * the implicit `*` default (one label, ICANN section).
 */
function matchPublicSuffix(labels: readonly string[], ruleSet: ReadonlySet<string>): SuffixMatch {
  const n = labels.length
  let bestCount = 1
  let bestRule: string | null = null
  for (let i = 0; i < n; i += 1) {
    const candidate = labels.slice(i).join('.')
    if (ruleSet.has(`!${candidate}`)) {
      const excRule = `!${candidate}`
      return {
        labelCount: Math.max(1, n - i - 1),
        matchedRule: excRule,
        section: PRIVATE_RULES.has(excRule) ? 'private' : 'icann',
      }
    }
    if (ruleSet.has(candidate) && n - i > bestCount) {
      bestCount = n - i
      bestRule = candidate
    }
    if (i < n - 1) {
      const wildRule = `*.${labels.slice(i + 1).join('.')}`
      if (ruleSet.has(wildRule) && n - i > bestCount) {
        bestCount = n - i
        bestRule = wildRule
      }
    }
  }
  return {
    labelCount: bestCount,
    matchedRule: bestRule,
    section: bestRule !== null && PRIVATE_RULES.has(bestRule) ? 'private' : 'icann',
  }
}

function publicSuffixLabelCount(labels: readonly string[]): number {
  return matchPublicSuffix(labels, RULES).labelCount
}

/** The public suffix of `hostname`, or null for IP literals / empty input. */
export function publicSuffix(hostname: string): string | null {
  const host = normalizeHostname(hostname)
  if (!host || isIpLiteralHost(host)) return null
  const labels = host.split('.').filter(Boolean)
  if (!labels.length) return null
  const count = Math.min(labels.length, publicSuffixLabelCount(labels))
  return labels.slice(-count).join('.')
}

/**
 * Returns `'private'` when `hostname` matches a PSL PRIVATE multi-tenant suffix (or
 * supplemental multi-tenant PaaS root), `'icann'` for standard ICANN TLD/ccTLD hosts,
 * or `null` for empty/IP-literal/single-label inputs.
 */
export function publicSuffixSection(hostname: string): 'icann' | 'private' | null {
  const host = normalizeHostname(hostname)
  if (!host || isIpLiteralHost(host)) return null
  const labels = host.split('.').filter(Boolean)
  if (labels.length < 2) return null
  const match = matchPublicSuffix(labels, RULES)
  if (match.section === 'private') return 'private'
  for (const root of SUPPLEMENTAL_MULTI_TENANT_ROOTS) {
    if (host === root || host.endsWith(`.${root}`)) return 'private'
  }
  return 'icann'
}

/**
 * True when `hostname` is or resides under a PSL PRIVATE multi-tenant suffix
 * (e.g. `vercel.app`, `my-app.vercel.app`, `bar.github.io`, `api.fly.dev`,
 * `d111111abcdef8.cloudfront.net`, `bucket.s3.amazonaws.com`, `acme-svc.a.run.app`).
 * Returns `false` for ICANN multi-part TLDs (`co.uk`, `baz.co.uk`, `com.au`) and
 * ordinary first-party domains.
 */
export function isMultiTenantPublicSuffix(hostname: string): boolean {
  return publicSuffixSection(hostname) === 'private'
}

/**
 * True when `hostname` is itself a public suffix (ICANN or PRIVATE section), e.g.
 * `github.io`, `vercel.app`, `s3.amazonaws.com`, `com.co`. Such hosts are shared
 * tenants: sibling hosts are NOT the same security principal.
 */
export function isPublicSuffixHost(hostname: string): boolean {
  const host = normalizeHostname(hostname)
  if (!host || isIpLiteralHost(host)) return false
  const labels = host.split('.').filter(Boolean)
  return publicSuffixLabelCount(labels) >= labels.length
}

/**
 * Registrable domain (public suffix + one label), or null when `hostname` is an IP
 * literal, a single-label host, or is itself a public/private suffix.
 */
export function registrableDomain(hostname: string): string | null {
  const host = normalizeHostname(hostname)
  if (!host || isIpLiteralHost(host)) return null
  const labels = host.split('.').filter(Boolean)
  if (labels.length < 2) return null
  const suffixCount = publicSuffixLabelCount(labels)
  if (labels.length <= suffixCount) return null
  return labels.slice(-(suffixCount + 1)).join('.')
}

/**
 * ICANN-only registrable domain (ignoring PSL PRIVATE section rules).
 * Useful for identifying the underlying vendor/platform apex of a CNAME target even
 * when the vendor itself is listed in the PSL PRIVATE section (e.g. `hosting.gitbook.io`
 * -> `gitbook.io`, `shops.myshopify.com` -> `myshopify.com`, `d111.cloudfront.net` ->
 * `cloudfront.net`, while `api.acme.co.uk` -> `acme.co.uk`).
 */
export function icannRegistrableDomain(hostname: string): string | null {
  const host = normalizeHostname(hostname)
  if (!host || isIpLiteralHost(host)) return null
  const labels = host.split('.').filter(Boolean)
  if (labels.length < 2) return null
  const suffixCount = matchPublicSuffix(labels, ICANN_RULES).labelCount
  if (labels.length <= suffixCount) return null
  return labels.slice(-(suffixCount + 1)).join('.')
}

/**
 * Canonical PSL-backed registrable apex for either a bare hostname or a full URL/origin
 * (e.g. `https://api.acme.co.uk:8443/v1` -> `acme.co.uk`, `deep.staging.acme.com.au` ->
 * `acme.com.au`, `co.uk` -> `null`, `vercel.app` -> `null`, `127.0.0.1` -> `null`).
 */
export function registrableApex(hostOrOrigin: string): string | null {
  const raw = hostOrOrigin.trim()
  if (!raw) return null
  let host = raw
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    try {
      host = new URL(raw).hostname
    } catch {
      return null
    }
  } else if (raw.includes('/') || (raw.includes(':') && !raw.startsWith('[') && raw.indexOf(':') === raw.lastIndexOf(':'))) {
    host = raw.replace(/\/.*$/, '').replace(/:\d+$/, '')
  }
  const normalized = normalizeHostname(host)
  if (!normalized || normalized === 'localhost' || isIpLiteralHost(normalized)) return null
  return registrableDomain(normalized)
}

/**
 * A host that may serve as a credential scope anchor: a registrable domain host
 * (including a tenant host such as `app.example.github.io`, whose registrable domain
 * is `example.github.io`) or an IP literal. Shared suffixes and opaque single-label
 * hosts are rejected because they cannot bound sibling access.
 */
export function isCredentialScopeHost(hostname: string): boolean {
  const host = normalizeHostname(hostname)
  if (!host) return false
  if (isIpLiteralHost(host)) return true
  if (!host.includes('.')) return false
  return registrableDomain(host) !== null
}
