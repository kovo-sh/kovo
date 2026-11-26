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
  routeStatuses: Record<string, CoverageClosureStatus>
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

export type RecordCoverageFieldName =
  | 'origin'
  | 'category'
  | 'status'
  | 'summary'
  | 'enforcingControl'
  | 'proofGapReason'
  | 'linkedFindingId'
  | 'route'
  | 'exchangeIds'

export interface RecordCoverageStatusRule {
  readonly status: CoverageClosureStatus
  /** Status-specific required non-empty fields (in addition to RECORD_COVERAGE_BASE_FIELDS). */
  readonly requiredFields: readonly RecordCoverageFieldName[]
  /** Whether the store requires >= 1 host-verified, run-owned, origin-matched broker exchangeId. */
  readonly requiresVerifiedExchange: boolean
  /** Minimum trimmed length for enforcingControl when required. */
  readonly minEnforcingControlLength?: number
  /** Minimum trimmed length for proofGapReason when required. */
  readonly minProofGapReasonLength?: number
  /** Unverified worker prose (e.g. raw /repos file:line without a live exchange) never closes coverage. */
  readonly acceptsUnverifiedRepoCitation: false
  /** Authoritative rule summary rendered into the tool schema and worker guidance. */
  readonly ruleSummary: string
}

export const RECORD_COVERAGE_BASE_FIELDS = ['origin', 'category', 'status', 'summary'] as const

/**
 * R3-15: Single authoritative `record_coverage` contract shared across:
 *   - `agent-session.ts` (tool JSON schema descriptions + pre-handler validation),
 *   - `store-findings.ts` (`upsertCoverageEntry` fail-closed validation), and
 *   - `assignment-brief.ts` (worker brief & settlement guidance).
 */
export const RECORD_COVERAGE_CONTRACT: Readonly<Record<CoverageClosureStatus, RecordCoverageStatusRule>> = {
  reported: {
    status: 'reported',
    requiredFields: ['linkedFindingId'],
    requiresVerifiedExchange: false,
    acceptsUnverifiedRepoCitation: false,
    ruleSummary: 'status="reported": REQUIRES linkedFindingId referencing a confirmed or static_verified finding.',
  },
  ruled_out: {
    status: 'ruled_out',
    requiredFields: ['enforcingControl', 'exchangeIds'],
    requiresVerifiedExchange: true,
    minEnforcingControlLength: 3,
    acceptsUnverifiedRepoCitation: false,
    ruleSummary: 'status="ruled_out": REQUIRES non-empty enforcingControl describing the verified guard AND >= 1 run-owned, origin-matched broker exchangeId in exchangeIds (or cited in enforcingControl). Unverified /repos file:line prose alone is rejected; if no live exchange exists, use status="needs_follow_up".',
  },
  no_issue_found: {
    status: 'no_issue_found',
    requiredFields: ['exchangeIds'],
    requiresVerifiedExchange: true,
    acceptsUnverifiedRepoCitation: false,
    ruleSummary: 'status="no_issue_found": REQUIRES >= 1 run-owned, origin-matched broker exchangeId in exchangeIds proving the route was probed on the live target (use status="needs_follow_up" if no live exchange exists).',
  },
  needs_follow_up: {
    status: 'needs_follow_up',
    requiredFields: ['proofGapReason'],
    requiresVerifiedExchange: false,
    minProofGapReasonLength: 5,
    acceptsUnverifiedRepoCitation: false,
    ruleSummary: 'status="needs_follow_up": REQUIRES a non-empty machine-readable proofGapReason (e.g. no_spec_shape, no_authenticated_persona, baseline_empty) explaining the exact blocker; use when no live exchange exists for a closure. Route-scoped: pass route="METHOD /path" so closing another route never hides this gap.',
  },
  not_applicable: {
    status: 'not_applicable',
    requiredFields: [],
    requiresVerifiedExchange: false,
    acceptsUnverifiedRepoCitation: false,
    ruleSummary: 'status="not_applicable": use only when the OWASP category surface does not exist on the target origin; state why in summary.',
  },
} as const

export type RecordCoverageContract = typeof RECORD_COVERAGE_CONTRACT

const COVERAGE_UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi
const COVERAGE_EXCHANGE_TOKEN_RE = /\b(?:gx|ex)[_-][A-Za-z0-9._-]{2,80}\b/g

/** Extract candidate broker exchange IDs from `exchangeIds` and embedded tokens in `enforcingControl`. */
export function extractCandidateCoverageExchangeIds(input: {
  exchangeIds?: readonly string[]
  enforcingControl?: string | null
}): string[] {
  return [...new Set([
    ...(input.exchangeIds ?? []),
    ...(input.enforcingControl
      ? [
          ...(input.enforcingControl.match(COVERAGE_UUID_RE) ?? []),
          ...(input.enforcingControl.match(COVERAGE_EXCHANGE_TOKEN_RE) ?? []),
        ]
      : []),
  ].map(id => id.trim()).filter(Boolean))]
}

/** Validate `record_coverage` arguments against the shared `RECORD_COVERAGE_CONTRACT`. */
export function validateRecordCoverageContractInput(
  input: {
    status: CoverageClosureStatus
    enforcingControl?: string | null
    proofGapReason?: string | null
    linkedFindingId?: string | null
    exchangeIds?: readonly string[]
  },
  options?: {
    proofGapCodes?: readonly string[]
    allowImplicitLinkedFinding?: boolean
  },
): {
  ok: true
  rule: RecordCoverageStatusRule
  candidateExchangeIds: string[]
} | {
  ok: false
  code: 'INVALID_COVERAGE_ARGS' | 'COVERAGE_EVIDENCE_REQUIRED'
  error: string
  rule: RecordCoverageStatusRule
} {
  const rule = RECORD_COVERAGE_CONTRACT[input.status]
  if (rule.requiredFields.includes('enforcingControl')) {
    const minLen = rule.minEnforcingControlLength ?? 1
    if (!input.enforcingControl || input.enforcingControl.trim().length < minLen) {
      return {
        ok: false,
        code: 'INVALID_COVERAGE_ARGS',
        error: rule.ruleSummary,
        rule,
      }
    }
  }
  if (rule.requiredFields.includes('proofGapReason')) {
    const minLen = rule.minProofGapReasonLength ?? 1
    if (!input.proofGapReason || input.proofGapReason.trim().length < minLen) {
      const codesSuffix = options?.proofGapCodes?.length
        ? ` Use a machine-readable code: ${options.proofGapCodes.join(', ')}.`
        : ''
      return {
        ok: false,
        code: 'INVALID_COVERAGE_ARGS',
        error: `${rule.ruleSummary}${codesSuffix}`,
        rule,
      }
    }
  }
  if (rule.requiredFields.includes('linkedFindingId') && !options?.allowImplicitLinkedFinding) {
    if (!input.linkedFindingId || !input.linkedFindingId.trim()) {
      return {
        ok: false,
        code: 'INVALID_COVERAGE_ARGS',
        error: rule.ruleSummary,
        rule,
      }
    }
  }
  const candidateExchangeIds = extractCandidateCoverageExchangeIds(input)
  if (rule.requiresVerifiedExchange && candidateExchangeIds.length === 0) {
    return {
      ok: false,
      code: 'COVERAGE_EVIDENCE_REQUIRED',
      error: `Coverage status "${input.status}" requires at least one run-owned, origin-matched exchangeId proving the route was probed. ${rule.ruleSummary}`,
      rule,
    }
  }
  return { ok: true, rule, candidateExchangeIds }
}

/** Generate the authoritative `record_coverage` tool description from `RECORD_COVERAGE_CONTRACT`. */
export function buildRecordCoverageToolDescription(): string {
  return [
    'Update the per-origin OWASP/API Top 10 closure coverage ledger (governed by RECORD_COVERAGE_CONTRACT):',
    `- ${RECORD_COVERAGE_CONTRACT.reported.ruleSummary}`,
    `- ${RECORD_COVERAGE_CONTRACT.ruled_out.ruleSummary}`,
    `- ${RECORD_COVERAGE_CONTRACT.no_issue_found.ruleSummary}`,
    `- ${RECORD_COVERAGE_CONTRACT.needs_follow_up.ruleSummary}`,
    `- ${RECORD_COVERAGE_CONTRACT.not_applicable.ruleSummary}`,
    'Proof gaps are route-scoped: a coded gap MUST name the route it applies to via route="METHOD /path" (e.g. route="GET /api/orders/:id"); a closure on one route never overwrites an open needs_follow_up gap on another route.',
  ].join(' ')
}

/** Generate `record_coverage` parameter descriptions directly from `RECORD_COVERAGE_CONTRACT`. */
export function buildRecordCoverageFieldDescriptions(proofGapCodes: readonly string[]): {
  enforcingControl: string
  proofGapReason: string
  route: string
  linkedFindingId: string
  exchangeIds: string
} {
  const requiredStatuses = (field: RecordCoverageFieldName): string =>
    (Object.values(RECORD_COVERAGE_CONTRACT) as RecordCoverageStatusRule[])
      .filter(r => r.requiredFields.includes(field))
      .map(r => `"${r.status}"`)
      .join(' or ')

  return {
    enforcingControl: `REQUIRED when status=${requiredStatuses('enforcingControl')}: concrete guard verified on the attacker path (must pair with >= 1 run-owned, origin-matched broker exchangeId in exchangeIds or cited here; unverified /repos file:line prose alone is rejected).`,
    proofGapReason: `REQUIRED when status=${requiredStatuses('proofGapReason')}: machine-readable code plus detail (${proofGapCodes.join('|')}) explaining the exact blocker; use when no live exchange exists.`,
    route: 'Route this closure applies to, as "METHOD /path" (path parameters may be concrete: "GET /api/orders/1001"). REQUIRED for a coded needs_follow_up gap when more than one route was probed, because per-route status keeps open gaps isolated from other routes.',
    linkedFindingId: `REQUIRED when status=${requiredStatuses('linkedFindingId')}: Finding ID linking to a confirmed or static_verified finding.`,
    exchangeIds: `REQUIRED when status=${requiredStatuses('exchangeIds')}: >= 1 run-owned, origin-matched broker exchangeId proving the route was probed on the live target (use status="needs_follow_up" if no live exchange exists).`,
  }
}

/** Compact single-line `record_coverage` contract summary for worker assignment briefs (<= 200 bytes). */
export function buildRecordCoverageBriefGuidance(): string {
  const req = (status: CoverageClosureStatus) => RECORD_COVERAGE_CONTRACT[status].requiredFields.join('+')
  return `record_coverage: reported(${req('reported')}); ruled_out(${req('ruled_out')}); no_issue_found(${req('no_issue_found')}); needs_follow_up(${req('needs_follow_up')}+route if no live exchange); not_applicable(summary).`
}

/**
 * Monotone rank for coverage closure statuses (R3-15 interim route-safe precedence):
 *   reported (4, confirmed)
 *   > needs_follow_up (3, open proof gap — cannot be silently hidden by a closure on another route)
 *   > ruled_out / no_issue_found / not_applicable (2, negative closure)
 *   > unprobed (0).
 */
export function coverageStatusRank(status: CoverageClosureStatus | 'unprobed'): number {
  switch (status) {
    case 'reported':
      return 4
    case 'needs_follow_up':
      return 3
    case 'ruled_out':
    case 'no_issue_found':
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
const ROUTE_STATUS_META_RE = /\[route_status=([^\]]+)\]/g
const BRANCH_META_RE = /\[branch=([^\]]+)\]/g
const EXCHANGES_META_RE = /\[exchanges=([^\]]+)\]/g
const ALL_META_TRAILERS_RE = /\s*\[(?:route|route_status|branch|exchanges)=[^\]]+\]/g

const STATUS_TO_CODE: Readonly<Record<CoverageClosureStatus, string>> = {
  reported: 'r',
  needs_follow_up: 'f',
  no_issue_found: 'n',
  ruled_out: 'x',
  not_applicable: 'a',
}

const CODE_TO_STATUS: Readonly<Record<string, CoverageClosureStatus>> = {
  r: 'reported',
  reported: 'reported',
  f: 'needs_follow_up',
  needs_follow_up: 'needs_follow_up',
  n: 'no_issue_found',
  no_issue_found: 'no_issue_found',
  x: 'ruled_out',
  ruled_out: 'ruled_out',
  a: 'not_applicable',
  not_applicable: 'not_applicable',
}

function sanitizeTagValue(value: string): string {
  return value.replace(/[\]\r\n]+/g, '').trim()
}

/** Normalize a route label (`METHOD /path`) for stable per-route status tracking. */
export function normalizeRouteForCoverage(route: string): string {
  const cleaned = sanitizeTagValue(route).replace(/,/g, '').replace(/\s+/g, ' ').trim()
  if (!cleaned) return ''
  const spaceIdx = cleaned.indexOf(' ')
  if (spaceIdx > 0) {
    const method = cleaned.slice(0, spaceIdx).toUpperCase()
    const path = cleaned.slice(spaceIdx + 1).trim().split(/[?#]/, 1)[0] || '/'
    return `${method} ${path}`
  }
  return cleaned.split(/[?#]/, 1)[0] || cleaned
}

/**
 * Parse structured route, per-route status, branchKey, and exchangeIds metadata preserved in
 * `coverage_entries` text fields (`summary`, `proofGapReason`, `enforcingControl`).
 */
export function extractCoverageEvidenceMetadata(row: {
  summary?: string | null
  enforcingControl?: string | null
  proofGapReason?: string | null
}): CoverageEvidenceMetadata {
  const routes: string[] = []
  const routeSeen = new Set<string>()
  const routeStatuses: Record<string, CoverageClosureStatus> = {}
  const addRoute = (raw: string): string[] => {
    const parsed: string[] = []
    for (const part of raw.split(',')) {
      const cleaned = normalizeRouteForCoverage(part)
      if (!cleaned) continue
      parsed.push(cleaned)
      if (!routeSeen.has(cleaned)) {
        routeSeen.add(cleaned)
        routes.push(cleaned)
      }
    }
    return parsed
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
    const fieldRoutes: string[] = []
    for (const match of field.matchAll(ROUTE_META_RE)) {
      if (match[1]) fieldRoutes.push(...addRoute(match[1]))
    }
    for (const match of field.matchAll(ROUTE_STATUS_META_RE)) {
      if (!match[1]) continue
      const tokens = match[1].split(',').map(sanitizeTagValue).filter(Boolean)
      for (let i = 0; i < tokens.length; i += 1) {
        const tok = tokens[i]!
        const eqIdx = tok.lastIndexOf('=')
        if (eqIdx > 0) {
          const r = normalizeRouteForCoverage(tok.slice(0, eqIdx))
          const st = CODE_TO_STATUS[tok.slice(eqIdx + 1).trim()]
          if (r && st) routeStatuses[r] = st
        } else {
          const st = CODE_TO_STATUS[tok]
          const r = fieldRoutes[i]
          if (r && st) routeStatuses[r] = st
        }
      }
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
    routeStatuses,
    branchKey,
    exchangeIds,
  }
}

/**
 * R3-15 route-safe per-category status aggregation:
 *   - Tracks each route's closure status individually inside `routeStatuses`.
 *   - Closing route A (`no_issue_found`/`ruled_out`) NEVER overwrites an open `needs_follow_up` gap on route B.
 *   - Later closing route B itself (same route) cleanly replaces route B's `needs_follow_up`, allowing the
 *     category cell to advance once no open `needs_follow_up` routes remain.
 */
export function mergeRouteCoverageStatuses(input: {
  existingStatus?: CoverageClosureStatus | null
  existingRoutes?: readonly string[]
  existingRouteStatuses?: Readonly<Record<string, CoverageClosureStatus>>
  incomingRoute?: string | null
  incomingStatus: CoverageClosureStatus
  allowDemotionFromReported?: boolean
}): {
  routeStatuses: Record<string, CoverageClosureStatus>
  derivedStatus: CoverageClosureStatus
  preservedExistingGap: boolean
} {
  const routeStatuses: Record<string, CoverageClosureStatus> = {}
  for (const [rawRoute, st] of Object.entries(input.existingRouteStatuses ?? {})) {
    const key = normalizeRouteForCoverage(rawRoute)
    if (key) routeStatuses[key] = st
  }
  if (input.existingStatus) {
    for (const rawRoute of input.existingRoutes ?? []) {
      const key = normalizeRouteForCoverage(rawRoute)
      if (key && !(key in routeStatuses)) {
        routeStatuses[key] = input.existingStatus
      }
    }
  }

  const incomingKey = input.incomingRoute ? normalizeRouteForCoverage(input.incomingRoute) : ''
  if (input.allowDemotionFromReported) {
    for (const [k, st] of Object.entries(routeStatuses)) {
      if (st === 'reported') delete routeStatuses[k]
    }
  }
  if (incomingKey) {
    const prevForRoute = routeStatuses[incomingKey]
    if (prevForRoute !== 'reported' || input.allowDemotionFromReported) {
      routeStatuses[incomingKey] = input.incomingStatus
    }
  }

  const trackedValues = Object.values(routeStatuses)
  const existingHadNoRoutes = (input.existingRoutes?.length ?? 0) === 0
    && Object.keys(input.existingRouteStatuses ?? {}).length === 0

  let derivedStatus: CoverageClosureStatus = input.incomingStatus
  if (!input.allowDemotionFromReported && trackedValues.includes('reported')) {
    derivedStatus = 'reported'
  } else if (trackedValues.includes('needs_follow_up')) {
    derivedStatus = 'needs_follow_up'
  } else if (
    input.existingStatus === 'needs_follow_up'
    && existingHadNoRoutes
    && coverageStatusRank(input.incomingStatus) < coverageStatusRank('needs_follow_up')
  ) {
    // An unscoped category-level gap (e.g. host quarantine) cannot be cleared by a single-route closure.
    derivedStatus = 'needs_follow_up'
  } else if (
    !input.allowDemotionFromReported
    && input.existingStatus
    && trackedValues.length === 0
    && coverageStatusRank(input.incomingStatus) < coverageStatusRank(input.existingStatus)
  ) {
    derivedStatus = input.existingStatus
  }

  return {
    routeStatuses,
    derivedStatus,
    preservedExistingGap: derivedStatus === 'needs_follow_up' && input.incomingStatus !== 'needs_follow_up',
  }
}

/**
 * Attach canonical `[route=...]`, `[route_status=...]`, `[branch=...]`, and `[exchanges=...]`
 * metadata to a coverage entry summary while clamping total length to 600 chars so metadata
 * is never silently truncated. When > 6 routes exist, higher-rank (`reported` / `needs_follow_up`)
 * routes are always retained first so open gaps are never evicted.
 */
export function appendCoverageEvidenceMetadata(
  summary: string,
  meta: {
    routes?: readonly string[]
    route?: string | null
    routeStatuses?: Readonly<Record<string, CoverageClosureStatus>>
    branchKey?: string | null
    exchangeIds?: readonly string[]
  },
): string {
  const base = summary.replace(ALL_META_TRAILERS_RE, '').trim()
  const normStatuses: Record<string, CoverageClosureStatus> = {}
  for (const [k, v] of Object.entries(meta.routeStatuses ?? {})) {
    const nk = normalizeRouteForCoverage(k)
    if (nk) normStatuses[nk] = v
  }
  const allRoutes = [...new Set([
    ...(meta.routes ?? []),
    ...(meta.route ? [meta.route] : []),
    ...Object.keys(normStatuses),
  ].map(normalizeRouteForCoverage).filter(Boolean))]
  const routes = allRoutes.length <= 6
    ? allRoutes
    : [...allRoutes]
        .sort((a, b) => coverageStatusRank(normStatuses[b] ?? 'unprobed') - coverageStatusRank(normStatuses[a] ?? 'unprobed'))
        .slice(0, 6)
  const branch = meta.branchKey ? sanitizeTagValue(meta.branchKey).slice(0, 120) : ''
  const exchanges = [...new Set((meta.exchangeIds ?? []).map(sanitizeTagValue).filter(Boolean))].slice(0, 8)

  const parts: string[] = []
  if (routes.length > 0) {
    parts.push(`[route=${routes.join(',')}]`)
    const hasAnyStatus = routes.some(r => r in normStatuses)
    if (hasAnyStatus) {
      const codes = routes.map(r => (normStatuses[r] ? STATUS_TO_CODE[normStatuses[r]!] : '')).join(',')
      if (codes.replace(/,/g, '').length > 0) {
        parts.push(`[route_status=${codes}]`)
      }
    }
  }
  if (branch) parts.push(`[branch=${branch}]`)
  if (exchanges.length > 0) parts.push(`[exchanges=${exchanges.join(',')}]`)
  if (parts.length === 0) return base.slice(0, 600)

  const trailer = parts.join(' ')
  const maxBaseLen = Math.max(0, 600 - trailer.length - (base ? 1 : 0))
  const clippedBase = base.slice(0, maxBaseLen).trimEnd()
  return clippedBase ? `${clippedBase} ${trailer}` : trailer.slice(0, 600)
}
