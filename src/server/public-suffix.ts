/**
 * Public Suffix List lookups for credential-scope decisions.
 *
 * The data file (`public-suffix-list.ts`) is the vendored multi-label subset of
 * https://publicsuffix.org/list/public_suffix_list.dat. Rules may be plain
 * (`co.uk`), wildcard (`*.ck`) or exception (`!www.ck`) entries, exactly as in the
 * upstream list. Plain single-label TLDs are covered by the PSL's implicit `*`
 * default rule, so they are not stored.
 *
 * This module is intentionally dependency-free: the previous hardcoded suffix set
 * silently widened scope to shared platform tenants (`github.io`, `vercel.app`,
 * `s3.amazonaws.com`, …) and ccTLD second levels (`com.co`).
 */
import { domainToASCII } from 'node:url'
import { publicSuffixRules } from './public-suffix-list.ts'

const RULES: ReadonlySet<string> = new Set(
  publicSuffixRules
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean),
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

/**
 * Number of trailing labels that form the public suffix for `labels`, following the
 * PSL algorithm: exception rules win, otherwise the longest matching rule, otherwise
 * the implicit `*` default (one label).
 */
function publicSuffixLabelCount(labels: readonly string[]): number {
  const n = labels.length
  let best = 1
  for (let i = 0; i < n; i += 1) {
    const candidate = labels.slice(i).join('.')
    if (RULES.has(candidate)) best = Math.max(best, n - i)
    // A wildcard rule `*.R` matches any suffix `X.R`; R is the candidate minus its first label.
    if (i < n - 1 && RULES.has(`*.${labels.slice(i + 1).join('.')}`)) best = Math.max(best, n - i)
    if (RULES.has(`!${candidate}`)) {
      // An exception rule removes its leftmost label from the public suffix.
      return Math.max(1, n - i - 1)
    }
  }
  return best
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
