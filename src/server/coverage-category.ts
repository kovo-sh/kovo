/**
 * R2-14 / R2-15 shared OWASP coverage category mapping, monotone coverage rank,
 * and structured evidence metadata helpers.
 *
 * Keeps `Finding.category` untouched (preserving benchmark grader keys) while
 * projecting every floor and agentic finding class into its canonical OWASP
 * coverage cell, and encodes/parses route, branchKey, and verified exchangeIds
 * inside existing `coverage_entries` text columns (no schema migration needed).
 */
import { owaspCategories, type CoverageClosureStatus, type OwaspCategory } from '../domain.ts'

export interface CoverageEvidenceMetadata {
  route: string | null
  routes: string[]
  branchKey: string | null
  exchangeIds: string[]
}

const OWASP_SET: ReadonlySet<string> = new Set(owaspCategories)

const CLASS_TO_OWASP: Readonly<Record<string, OwaspCategory>> = {
  // Broken Access Control
  'broken-access-control': 'broken-access-control',
  bola: 'broken-access-control',
  bfla: 'broken-access-control',
  idor: 'broken-access-control',
  authz: 'broken-access-control',
  authorization: 'broken-access-control',
  'access-control': 'broken-access-control',
  'privilege-escalation': 'broken-access-control',
  privesc: 'broken-access-control',
  'cross-tenant': 'broken-access-control',
  'cross-tenant-write': 'broken-access-control',
  'cross-tenant-read': 'broken-access-control',
  'mass-assignment': 'broken-access-control',
  graphql: 'broken-access-control',
  'graphql-bola': 'broken-access-control',
  'graphql-bfla': 'broken-access-control',
  'graphql-authz': 'broken-access-control',
  'object-level-authz': 'broken-access-control',
  'function-level-authz': 'broken-access-control',
  'path-traversal': 'broken-access-control',
  'directory-traversal': 'broken-access-control',
  lfi: 'broken-access-control',
  'local-file-inclusion': 'broken-access-control',
  'arbitrary-file-read': 'broken-access-control',
  'file-inclusion': 'broken-access-control',
  'force-browsing': 'broken-access-control',
  'insecure-direct-object-reference': 'broken-access-control',

  // Auth & Identity
  'auth-identity': 'auth-identity',
  jwt: 'auth-identity',
  'jwt-none': 'auth-identity',
  'jwt-forgery': 'auth-identity',
  auth: 'auth-identity',
  authn: 'auth-identity',
  authentication: 'auth-identity',
  'broken-auth': 'auth-identity',
  'broken-authentication': 'auth-identity',
  'weak-auth': 'auth-identity',
  'auth-bypass': 'auth-identity',
  session: 'auth-identity',
  'session-fixation': 'auth-identity',
  'session-hijacking': 'auth-identity',
  oauth: 'auth-identity',
  oidc: 'auth-identity',
  saml: 'auth-identity',
  sso: 'auth-identity',
  mfa: 'auth-identity',
  'mfa-bypass': 'auth-identity',
  'password-reset': 'auth-identity',
  'account-takeover': 'auth-identity',
  ato: 'auth-identity',
  'credential-stuffing': 'auth-identity',
  'brute-force': 'auth-identity',
  'token-forgery': 'auth-identity',
  webhook: 'auth-identity',
  'webhook-forgery': 'auth-identity',
  'webhook-signature': 'auth-identity',
  'hmac-bypass': 'auth-identity',
  'signature-bypass': 'auth-identity',

  // Injection & Input Validation
  'injection-input': 'injection-input',
  sqli: 'injection-input',
  'sql-injection': 'injection-input',
  nosqli: 'injection-input',
  'nosql-injection': 'injection-input',
  cmdi: 'injection-input',
  'command-injection': 'injection-input',
  'os-command-injection': 'injection-input',
  'code-injection': 'injection-input',
  rce: 'injection-input',
  ssti: 'injection-input',
  'template-injection': 'injection-input',
  xxe: 'injection-input',
  'blind-xxe': 'injection-input',
  'xml-external-entity': 'injection-input',
  ldapi: 'injection-input',
  'ldap-injection': 'injection-input',
  'xpath-injection': 'injection-input',
  crlf: 'injection-input',
  'crlf-injection': 'injection-input',
  'header-injection': 'injection-input',
  deserialization: 'injection-input',
  'insecure-deserialization': 'injection-input',
  'prototype-pollution': 'injection-input',
  injection: 'injection-input',
  'eval-injection': 'injection-input',
  'expression-language': 'injection-input',
  'el-injection': 'injection-input',
  ognl: 'injection-input',
  'log-injection': 'injection-input',
  'http-request-smuggling': 'injection-input',
  'request-smuggling': 'injection-input',
  smuggling: 'injection-input',
  cache: 'injection-input',
  'cache-poisoning': 'injection-input',
  'cwe-89': 'injection-input',

  // CORS & Client-Side
  'cors-client-side': 'cors-client-side',
  xss: 'cors-client-side',
  'xss-reflected': 'cors-client-side',
  'reflected-xss': 'cors-client-side',
  'xss-stored': 'cors-client-side',
  'stored-xss': 'cors-client-side',
  'dom-xss': 'cors-client-side',
  'cross-site-scripting': 'cors-client-side',
  csrf: 'cors-client-side',
  xsrf: 'cors-client-side',
  'cross-site-request-forgery': 'cors-client-side',
  cors: 'cors-client-side',
  'cors-misconfiguration': 'cors-client-side',
  clickjacking: 'cors-client-side',
  postmessage: 'cors-client-side',
  'dom-clobbering': 'cors-client-side',
  csti: 'cors-client-side',
  'client-side': 'cors-client-side',
  tabnabbing: 'cors-client-side',
  'websocket-hijacking': 'cors-client-side',
  cswsh: 'cors-client-side',

  // SSRF & Redirects
  'ssrf-redirects': 'ssrf-redirects',
  ssrf: 'ssrf-redirects',
  'blind-ssrf': 'ssrf-redirects',
  'oob-ssrf': 'ssrf-redirects',
  oob: 'ssrf-redirects',
  'server-side-request-forgery': 'ssrf-redirects',
  'open-redirect': 'ssrf-redirects',
  'unvalidated-redirect': 'ssrf-redirects',
  'url-redirect': 'ssrf-redirects',
  redirect: 'ssrf-redirects',

  // Crypto, TLS & Transport
  'crypto-tls-transport': 'crypto-tls-transport',
  crypto: 'crypto-tls-transport',
  cryptography: 'crypto-tls-transport',
  'weak-crypto': 'crypto-tls-transport',
  tls: 'crypto-tls-transport',
  ssl: 'crypto-tls-transport',
  hsts: 'crypto-tls-transport',
  'weak-cipher': 'crypto-tls-transport',
  'plaintext-transport': 'crypto-tls-transport',
  cleartext: 'crypto-tls-transport',
  'weak-hash': 'crypto-tls-transport',
  'padding-oracle': 'crypto-tls-transport',
  'insecure-random': 'crypto-tls-transport',
  prng: 'crypto-tls-transport',
  'weak-secret': 'crypto-tls-transport',
  'cookie-flags': 'crypto-tls-transport',
  'insecure-cookie': 'crypto-tls-transport',

  // Misconfiguration & Exposure
  'misconfig-exposure': 'misconfig-exposure',
  misconfig: 'misconfig-exposure',
  misconfiguration: 'misconfig-exposure',
  'security-misconfiguration': 'misconfig-exposure',
  'info-disclosure': 'misconfig-exposure',
  'information-disclosure': 'misconfig-exposure',
  'sensitive-data-exposure': 'misconfig-exposure',
  'secret-disclosure': 'misconfig-exposure',
  secrets: 'misconfig-exposure',
  'secret-leak': 'misconfig-exposure',
  'data-exposure': 'misconfig-exposure',
  'pii-exposure': 'misconfig-exposure',
  'stack-trace': 'misconfig-exposure',
  'debug-exposure': 'misconfig-exposure',
  'directory-listing': 'misconfig-exposure',
  csp: 'misconfig-exposure',
  'security-headers': 'misconfig-exposure',
  'graphql-introspection': 'misconfig-exposure',
  'verbose-error': 'misconfig-exposure',
  'source-disclosure': 'misconfig-exposure',
  'backup-file': 'misconfig-exposure',
  'env-exposure': 'misconfig-exposure',
  'swagger-exposure': 'misconfig-exposure',

  // Upload & Storage
  'upload-storage': 'upload-storage',
  upload: 'upload-storage',
  'file-upload': 'upload-storage',
  'unrestricted-upload': 'upload-storage',
  'arbitrary-file-upload': 'upload-storage',
  'zip-slip': 'upload-storage',
  'polyglot-upload': 'upload-storage',
  storage: 'upload-storage',
  'bucket-exposure': 'upload-storage',
  's3-exposure': 'upload-storage',
  'blob-exposure': 'upload-storage',
  'arbitrary-file-write': 'upload-storage',

  // Business Logic & Race
  'business-logic-race': 'business-logic-race',
  race: 'business-logic-race',
  'race-condition': 'business-logic-race',
  'race-double-spend': 'business-logic-race',
  'double-spend': 'business-logic-race',
  toctou: 'business-logic-race',
  'business-logic': 'business-logic-race',
  'logic-flaw': 'business-logic-race',
  'price-tampering': 'business-logic-race',
  'price-manipulation': 'business-logic-race',
  'negative-quantity': 'business-logic-race',
  'coupon-abuse': 'business-logic-race',
  'workflow-bypass': 'business-logic-race',
  'state-machine': 'business-logic-race',
  'state-bypass': 'business-logic-race',
  'payment-bypass': 'business-logic-race',
  'limit-bypass': 'business-logic-race',
  'quota-bypass': 'business-logic-race',
  'replay-attack': 'business-logic-race',
  'rate-limit-bypass': 'business-logic-race',

  // DNS Takeover & Infrastructure
  'dns-takeover-infra': 'dns-takeover-infra',
  dns: 'dns-takeover-infra',
  'dns-takeover': 'dns-takeover-infra',
  'subdomain-takeover': 'dns-takeover-infra',
  'dangling-cname': 'dns-takeover-infra',
  'host-header': 'dns-takeover-infra',
  'host-header-injection': 'dns-takeover-infra',
  infra: 'dns-takeover-infra',
  infrastructure: 'dns-takeover-infra',
  'container-escape': 'dns-takeover-infra',
  'cloud-metadata': 'dns-takeover-infra',
  imds: 'dns-takeover-infra',
  kubernetes: 'dns-takeover-infra',
  k8s: 'dns-takeover-infra',

  // LLM & AI Security
  'llm-ai-security': 'llm-ai-security',
  llm: 'llm-ai-security',
  'prompt-injection': 'llm-ai-security',
  'indirect-prompt-injection': 'llm-ai-security',
  'ai-security': 'llm-ai-security',
  'model-extraction': 'llm-ai-security',
  'tool-abuse': 'llm-ai-security',
  'rag-poisoning': 'llm-ai-security',
}

const PREFIX_FALLBACKS: ReadonlyArray<readonly [RegExp, OwaspCategory]> = [
  [/^(?:sqli|sql|nosql|cmdi|command|ssti|xxe|ldap|xpath|crlf|deser|proto|smuggl|cache)/, 'injection-input'],
  [/^(?:bola|bfla|idor|authz|access|priv|cross-tenant|mass-assign|graphql|path-travers|dir-travers|lfi)/, 'broken-access-control'],
  [/^(?:jwt|auth|session|oauth|oidc|saml|mfa|sso|password|webhook|token)/, 'auth-identity'],
  [/^(?:xss|csrf|xsrf|cors|clickjack|dom-|postmessage)/, 'cors-client-side'],
  [/^(?:ssrf|redirect|open-redirect|oob)/, 'ssrf-redirects'],
  [/^(?:race|double-spend|price-|workflow|business-logic|toctou|coupon|quota)/, 'business-logic-race'],
  [/^(?:upload|file-upload|zip-slip|storage|bucket|s3)/, 'upload-storage'],
  [/^(?:crypto|tls|ssl|hsts|cipher|cookie)/, 'crypto-tls-transport'],
  [/^(?:info|secret|misconfig|debug|swagger|env-|backup|pii|data-expos|sensitive-data)/, 'misconfig-exposure'],
  [/^(?:dns|subdomain|host-header|imds|k8s|kube|infra)/, 'dns-takeover-infra'],
  [/^(?:llm|prompt-|rag-|ai-)/, 'llm-ai-security'],
]

/**
 * Project any floor or agentic finding category / vulnClass / intent string
 * onto its canonical OWASP coverage cell without mutating `Finding.category`.
 */
export function categoryToOwaspCoverageCategory(category: string | null | undefined): OwaspCategory | null {
  if (!category || typeof category !== 'string') return null
  const trimmed = category.trim().toLowerCase()
  if (!trimmed) return null
  if (OWASP_SET.has(trimmed)) return trimmed as OwaspCategory
  const normalized = trimmed.replace(/[\s_/]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '')
  if (!normalized) return null
  if (OWASP_SET.has(normalized)) return normalized as OwaspCategory
  const exact = CLASS_TO_OWASP[normalized]
  if (exact) return exact
  for (const [pattern, mapped] of PREFIX_FALLBACKS) {
    if (pattern.test(normalized)) return mapped
  }
  return null
}

/**
 * Monotone rank for coverage closure statuses:
 *   reported (confirmed) > ruled_out / no_issue_found / needs_follow_up / not_applicable (probed) > unprobed.
 */
export function coverageStatusRank(status: CoverageClosureStatus | 'unprobed'): number {
  switch (status) {
    case 'reported':
      return 3
    case 'ruled_out':
    case 'no_issue_found':
    case 'needs_follow_up':
    case 'not_applicable':
      return 2
    case 'unprobed':
    default:
      return 0
  }
}

/** Normalize an origin string for strict origin-match comparisons. */
export function normalizeOriginForCoverage(origin: string): string {
  const trimmed = origin.trim()
  if (!trimmed) return ''
  try {
    return new URL(trimmed).origin.toLowerCase()
  } catch {
    return trimmed.replace(/\/+$/, '').toLowerCase()
  }
}

const ROUTE_META_RE = /\[route=([^\]]+)\]/g
const BRANCH_META_RE = /\[branch=([^\]]+)\]/g
const EXCHANGES_META_RE = /\[exchanges=([^\]]+)\]/g
const ALL_META_TRAILERS_RE = /\s*\[(?:route|branch|exchanges)=[^\]]+\]/g

function sanitizeTagValue(value: string): string {
  return value.replace(/[\]\r\n]+/g, '').trim()
}

/**
 * Parse structured route, branchKey, and exchangeIds metadata preserved in
 * `coverage_entries` text fields (`summary`, `proofGapReason`, `enforcingControl`).
 */
export function extractCoverageEvidenceMetadata(row: {
  summary?: string | null
  enforcingControl?: string | null
  proofGapReason?: string | null
}): CoverageEvidenceMetadata {
  const routes: string[] = []
  const routeSeen = new Set<string>()
  const addRoute = (raw: string) => {
    for (const part of raw.split(',')) {
      const cleaned = sanitizeTagValue(part)
      if (!cleaned || routeSeen.has(cleaned)) continue
      routeSeen.add(cleaned)
      routes.push(cleaned)
    }
  }

  let branchKey: string | null = null
  const exchangeIds: string[] = []
  const exSeen = new Set<string>()
  const addExchanges = (raw: string) => {
    for (const part of raw.split(',')) {
      const cleaned = sanitizeTagValue(part)
      if (!cleaned || exSeen.has(cleaned)) continue
      exSeen.add(cleaned)
      exchangeIds.push(cleaned)
    }
  }

  for (const field of [row.summary, row.proofGapReason, row.enforcingControl]) {
    if (!field) continue
    for (const match of field.matchAll(ROUTE_META_RE)) {
      if (match[1]) addRoute(match[1])
    }
    for (const match of field.matchAll(BRANCH_META_RE)) {
      if (match[1]) {
        const cleaned = sanitizeTagValue(match[1])
        if (cleaned) branchKey = cleaned
      }
    }
    for (const match of field.matchAll(EXCHANGES_META_RE)) {
      if (match[1]) addExchanges(match[1])
    }
  }

  return {
    route: routes[0] ?? null,
    routes,
    branchKey,
    exchangeIds,
  }
}

/**
 * Attach canonical `[route=...]`, `[branch=...]`, and `[exchanges=...]` metadata
 * to a coverage entry summary while clamping total length to 600 chars so metadata
 * is never silently truncated.
 */
export function appendCoverageEvidenceMetadata(
  summary: string,
  meta: {
    routes?: readonly string[]
    route?: string | null
    branchKey?: string | null
    exchangeIds?: readonly string[]
  },
): string {
  const base = summary.replace(ALL_META_TRAILERS_RE, '').trim()
  const routes = [...new Set([
    ...(meta.routes ?? []),
    ...(meta.route ? [meta.route] : []),
  ].map(sanitizeTagValue).filter(Boolean))].slice(0, 6)
  const branch = meta.branchKey ? sanitizeTagValue(meta.branchKey).slice(0, 120) : ''
  const exchanges = [...new Set((meta.exchangeIds ?? []).map(sanitizeTagValue).filter(Boolean))].slice(0, 8)

  const parts: string[] = []
  if (routes.length > 0) parts.push(`[route=${routes.join(',')}]`)
  if (branch) parts.push(`[branch=${branch}]`)
  if (exchanges.length > 0) parts.push(`[exchanges=${exchanges.join(',')}]`)
  if (parts.length === 0) return base.slice(0, 600)

  const trailer = parts.join(' ')
  const maxBaseLen = Math.max(0, 600 - trailer.length - (base ? 1 : 0))
  const clippedBase = base.slice(0, maxBaseLen).trimEnd()
  return clippedBase ? `${clippedBase} ${trailer}` : trailer.slice(0, 600)
}
