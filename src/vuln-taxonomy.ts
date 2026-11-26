/**
 * Single canonical vulnerability-class taxonomy (`R3-11`).
 *
 * Authoritative source of truth for:
 *   - receipt/finding class -> canonical CWE, accepted CWE family, OWASP coverage cell, and
 *     reporting attribution (`label`, `impact`, `remediation`);
 *   - canonical class -> OWASP coverage cell map shared with `src/server/coverage-category.ts`;
 *   - derived CWE-family sets enforced by the semantic deduplication veto in `src/server/dedupe.ts`
 *     (derived directly from `VULN_TAXONOMY` with explicit documented veto exceptions — zero parallel
 *     hand-maintained CWE tables).
 *
 * Unknown receipt classes map explicitly to `'unclassified'` so they stay visible as a taxonomy
 * gap instead of silently falling through to `CWE-200` / `misconfig-exposure`.
 *
 * Keep this module browser-safe (zero `node:*` and zero `src/server/*` imports).
 */
import type { OwaspCategory } from './domain.ts'
import { normalizeCwe } from './finding-keys.ts'

export const UNCLASSIFIED_TAXONOMY_KEY = 'unclassified' as const
export type TaxonomyCategory = OwaspCategory | typeof UNCLASSIFIED_TAXONOMY_KEY

export interface VulnTaxonomyEntry {
  readonly id: string
  readonly aliases: readonly string[]
  readonly canonicalCwe: string
  readonly cweFamily: readonly string[]
  /** Canonical semantic dedupe family key derived directly into `DEDUPE_CWE_FAMILIES_BY_CWE`. */
  readonly dedupeFamily: string
  readonly owaspCategory: OwaspCategory
  readonly label: string
  readonly impact: string
  readonly remediation: string
}

export interface ReceiptCweFamily {
  readonly cwe: string
  readonly family: readonly string[]
  readonly category: TaxonomyCategory
  readonly unclassified: boolean
}

export interface VulnProofAttribution {
  readonly label: string
  readonly cwe: string
  readonly category: TaxonomyCategory
  readonly unclassified: boolean
  readonly impact: string
  readonly remediation: string
}

export interface DedupeFamilyException {
  readonly entryId: string
  readonly cwe: string
  readonly reason: string
}

/**
 * Frozen canonical vulnerability-class taxonomy table.
 * Derived consumers (`exec-verify.ts`, `coverage-category.ts`, `dedupe.ts`) MUST read from this
 * table rather than maintaining parallel regex ladders or separate CWE-family maps.
 */
export const VULN_TAXONOMY: readonly VulnTaxonomyEntry[] = Object.freeze([
  {
    id: 'bola',
    aliases: [
      'bola',
      'boli',
      'idor',
      'cross_tenant',
      'cross_tenant_read',
      'cross_tenant_write',
      'authorization',
      'access_control',
      'broken_access_control',
      'object_level_authz',
      'insecure_direct_object_reference',
      'graphql_bola',
      'graphql_authz',
      'signed_url_mint',
      'presigned_url_mint',
      'signed_url_traversal',
      'storage_signed_url',
      'gcs_signed_url',
      's3_presigned_url',
      'azure_sas_mint',
    ],
    canonicalCwe: 'CWE-639',
    cweFamily: ['CWE-639', 'CWE-284', 'CWE-285', 'CWE-862', 'CWE-863', 'CWE-566', 'CWE-1220'],
    dedupeFamily: 'authorization',
    owaspCategory: 'broken-access-control',
    label: 'broken object-level authorization',
    impact: 'An authenticated actor read or changed a resource owned by another tenant or user.',
    remediation: 'Enforce an object-level authorization check on every request that names a resource id.',
  },
  {
    id: 'dual_tenant_abac',
    aliases: ['dual_tenant_abac'],
    canonicalCwe: 'CWE-639',
    cweFamily: ['CWE-639', 'CWE-284', 'CWE-285', 'CWE-862', 'CWE-863', 'CWE-566', 'CWE-1220'],
    dedupeFamily: 'authorization',
    owaspCategory: 'broken-access-control',
    label: 'cross-tenant ABAC authorization bypass',
    impact: 'An actor crossed a multi-tenant or role-matrix authorization boundary via a chained sequence.',
    remediation: 'Enforce tenant and object-level authorization invariants uniformly on every read, batch, and mutation path.',
  },
  {
    id: 'bfla',
    aliases: ['bfla', 'privilege_escalation', 'privesc', 'function_level_authz', 'graphql_bfla'],
    canonicalCwe: 'CWE-285',
    cweFamily: ['CWE-285', 'CWE-269', 'CWE-862', 'CWE-863', 'CWE-639', 'CWE-284', 'CWE-566', 'CWE-1220'],
    dedupeFamily: 'authorization',
    owaspCategory: 'broken-access-control',
    label: 'broken function-level authorization',
    impact: 'A lower-privileged actor invoked a privileged function that should be role-gated.',
    remediation: 'Gate the function server-side on the caller role, not on client-side visibility.',
  },
  {
    id: 'mass_assignment',
    aliases: ['mass_assignment'],
    canonicalCwe: 'CWE-915',
    cweFamily: ['CWE-915', 'CWE-285', 'CWE-863'],
    dedupeFamily: 'mass_assignment',
    owaspCategory: 'broken-access-control',
    label: 'mass assignment',
    impact: 'An over-posted field persisted a value the actor was not allowed to set.',
    remediation: 'Allowlist assignable fields and bind them explicitly server-side.',
  },
  {
    id: 'path_traversal',
    aliases: [
      'path_traversal',
      'directory_traversal',
      'lfi',
      'local_file_inclusion',
      'arbitrary_file_read',
      'file_inclusion',
    ],
    canonicalCwe: 'CWE-22',
    cweFamily: ['CWE-22', 'CWE-23', 'CWE-73'],
    dedupeFamily: 'path_traversal',
    owaspCategory: 'broken-access-control',
    label: 'path traversal',
    impact: 'Path input escaped the intended base directory on the server.',
    remediation: 'Resolve canonical paths and verify they remain inside the allowed root directory.',
  },
  {
    id: 'sqli',
    aliases: [
      'sqli',
      'sql_injection',
      'sqli_error',
      'sql_boolean',
      'sql_boolean_diff',
      'boolean_sqli',
      'boolean_differential',
      'blind_sqli',
      'sqli_status',
      'sql_status',
      'sql_status_diff',
      'status_sqli',
      'status_boolean',
      'sqli_time',
      'sql_time',
      'timing',
    ],
    canonicalCwe: 'CWE-89',
    // One-directional: specific SQLi receipts accept generic CWE-74 proposals, never the reverse.
    cweFamily: ['CWE-89', 'CWE-564', 'CWE-74'],
    dedupeFamily: 'sqli',
    owaspCategory: 'injection-input',
    label: 'SQL injection',
    impact: 'Injected input changed the SQL query structure or timing of the server-side operation.',
    remediation: 'Use parameterized queries / prepared statements; never concatenate input into SQL.',
  },
  {
    id: 'nosqli',
    aliases: ['nosqli', 'nosql_injection'],
    canonicalCwe: 'CWE-943',
    // One-directional: specific NoSQLi receipts accept generic CWE-74 proposals, never CWE-89.
    cweFamily: ['CWE-943', 'CWE-74'],
    dedupeFamily: 'nosqli',
    owaspCategory: 'injection-input',
    label: 'NoSQL injection',
    impact: 'Injected query operators or predicates altered a server-side NoSQL query.',
    remediation: 'Validate and coerce input types strictly and reject untrusted query operator objects.',
  },
  {
    id: 'ssti',
    aliases: ['ssti', 'template_injection'],
    canonicalCwe: 'CWE-1336',
    cweFamily: ['CWE-1336', 'CWE-94', 'CWE-74'],
    dedupeFamily: 'ssti',
    owaspCategory: 'injection-input',
    label: 'server-side template injection',
    impact: 'Untrusted input was evaluated by a server-side template engine.',
    remediation: 'Pass user input as template data rather than compiling it as template source; use a logic-less or sandboxed template context.',
  },
  {
    id: 'command_injection',
    aliases: ['command_injection', 'os_command_injection', 'cmdi', 'rce', 'code_injection', 'eval_injection'],
    canonicalCwe: 'CWE-78',
    cweFamily: ['CWE-78', 'CWE-77', 'CWE-94', 'CWE-74'],
    dedupeFamily: 'cmdi',
    owaspCategory: 'injection-input',
    label: 'command injection',
    impact: 'Injected input altered a server-side OS command execution.',
    remediation: 'Pass arguments as an argv array without a shell and strictly allowlist dynamic parameters.',
  },
  {
    id: 'injection',
    aliases: ['injection', 'injection_input'],
    canonicalCwe: 'CWE-74',
    // Tight by design (F1): generic `injection` receipt accepts ONLY CWE-74 so it can never
    // satisfy a specific confirmed CWE-89/CWE-78/CWE-1336/CWE-943 drift check on reverify.
    cweFamily: ['CWE-74'],
    dedupeFamily: 'injection_generic',
    owaspCategory: 'injection-input',
    label: 'injection',
    impact: 'Injected input changed the query/command structure or timing of the server-side operation.',
    remediation: 'Use parameterized queries and context-appropriate encoding; never concatenate input into a command.',
  },
  {
    id: 'xxe',
    aliases: ['xxe', 'blind_xxe', 'xml_external_entity'],
    canonicalCwe: 'CWE-611',
    cweFamily: ['CWE-611'],
    dedupeFamily: 'xxe',
    owaspCategory: 'injection-input',
    label: 'XML external entity injection',
    impact: 'The XML parser resolved an attacker-supplied external entity or out-of-band canary.',
    remediation: 'Disable external entities and DTD processing in the XML parser.',
  },
  {
    id: 'parser_cache_differential',
    aliases: [
      'parser_cache_differential',
      'cache_poisoning',
      'cache_deception',
      'request_smuggling',
      'http_request_smuggling',
      'smuggling',
    ],
    canonicalCwe: 'CWE-444',
    cweFamily: ['CWE-444', 'CWE-436', 'CWE-525'],
    dedupeFamily: 'parser_cache',
    owaspCategory: 'injection-input',
    label: 'parser / cache differential boundary bypass',
    impact: 'A parser or cache key differential between surfaces bypassed access or tenant isolation.',
    remediation: 'Normalize parsing across layers and key shared caches by tenant and authenticated identity.',
  },
  {
    id: 'xss',
    aliases: [
      'xss',
      'xss_stored',
      'stored_xss',
      'xss_reflected',
      'reflected_xss',
      'dom_xss',
      'browser_xss',
      'browser_dom',
      'cross_site_scripting',
      'markup',
      'html_injection',
    ],
    canonicalCwe: 'CWE-79',
    cweFamily: ['CWE-79', 'CWE-80', 'CWE-83'],
    dedupeFamily: 'xss',
    owaspCategory: 'cors-client-side',
    label: 'cross-site scripting',
    impact: 'Actor-supplied markup was stored or reflected and executed in another user’s browser context.',
    remediation: 'Encode output for the HTML context and apply a restrictive Content-Security-Policy.',
  },
  {
    id: 'csrf',
    aliases: ['csrf', 'xsrf', 'cross_site_request_forgery'],
    canonicalCwe: 'CWE-352',
    cweFamily: ['CWE-352'],
    dedupeFamily: 'csrf',
    owaspCategory: 'cors-client-side',
    label: 'cross-site request forgery',
    impact: 'A cross-site request performed a state change as the victim without a valid intent token.',
    remediation: 'Require a per-session anti-CSRF token (or SameSite=Lax cookies) on state-changing routes.',
  },
  {
    id: 'postmessage',
    aliases: ['postmessage'],
    canonicalCwe: 'CWE-346',
    cweFamily: ['CWE-346', 'CWE-942'],
    dedupeFamily: 'cors',
    owaspCategory: 'cors-client-side',
    label: 'insecure postMessage origin validation',
    impact: 'A client-side postMessage handler trusted messages from an unverified origin.',
    remediation: 'Validate event.origin against an explicit allowlist before acting on postMessage payloads.',
  },
  {
    id: 'cors_misconfiguration',
    aliases: ['cors_misconfiguration'],
    canonicalCwe: 'CWE-942',
    cweFamily: ['CWE-942', 'CWE-346'],
    dedupeFamily: 'cors',
    owaspCategory: 'cors-client-side',
    label: 'permissive CORS configuration',
    impact: 'Cross-origin responses reflected untrusted origins or exposed authenticated data cross-origin.',
    remediation: 'Allowlist trusted origins explicitly and never reflect arbitrary Origin headers with credentials.',
  },
  {
    id: 'security_headers',
    aliases: ['security_headers', 'csp'],
    canonicalCwe: 'CWE-693',
    cweFamily: ['CWE-693', 'CWE-1021'],
    dedupeFamily: 'security_headers',
    owaspCategory: 'misconfig-exposure',
    label: 'missing or weak security headers',
    impact: 'Missing browser protection headers weakened defense-in-depth against client-side attacks.',
    remediation: 'Serve restrictive Content-Security-Policy, X-Content-Type-Options, and framing protection headers.',
  },
  {
    id: 'cookie_flags',
    aliases: ['cookie_flags', 'insecure_cookie'],
    canonicalCwe: 'CWE-614',
    cweFamily: ['CWE-614', 'CWE-1004', 'CWE-1275'],
    dedupeFamily: 'cookie_flags',
    owaspCategory: 'crypto-tls-transport',
    label: 'insecure cookie attributes',
    impact: 'Session cookies lacked Secure, HttpOnly, or SameSite attributes.',
    remediation: 'Set Secure, HttpOnly, and an appropriate SameSite attribute on all authentication cookies.',
  },
  {
    id: 'transport_crypto',
    aliases: ['plaintext_transport', 'weak_cipher'],
    canonicalCwe: 'CWE-319',
    cweFamily: ['CWE-319', 'CWE-295', 'CWE-327'],
    dedupeFamily: 'transport_crypto',
    owaspCategory: 'crypto-tls-transport',
    label: 'weak transport or cryptographic posture',
    impact: 'Traffic or secrets relied on weak TLS/cipher settings or unencrypted transport.',
    remediation: 'Enforce modern TLS (1.2+) with HSTS and strong AEAD cipher suites.',
  },
  {
    id: 'ssrf',
    aliases: ['ssrf', 'blind_ssrf', 'oob_ssrf', 'oob', 'server_side_request_forgery'],
    canonicalCwe: 'CWE-918',
    cweFamily: ['CWE-918'],
    dedupeFamily: 'ssrf',
    owaspCategory: 'ssrf-redirects',
    label: 'server-side request forgery',
    impact: 'The target fetched an attacker-supplied destination or out-of-band canary.',
    remediation: 'Allowlist outbound destinations and block private, loopback, and link-local IP ranges after DNS resolution.',
  },
  {
    id: 'cross_surface_pivot',
    aliases: ['cross_surface_pivot'],
    canonicalCwe: 'CWE-918',
    cweFamily: ['CWE-918'],
    dedupeFamily: 'ssrf',
    owaspCategory: 'ssrf-redirects',
    label: 'cross-surface multi-hop privilege pivot',
    impact: 'An attacker-origin chain pivoted across application surfaces to reach a protected internal or privileged action.',
    remediation: 'Enforce strict authentication, allowlists, and provenance checks at every cross-service and async boundary.',
  },
  {
    id: 'open_redirect',
    aliases: ['open_redirect', 'redirect', 'url_redirect', 'unvalidated_redirect'],
    canonicalCwe: 'CWE-601',
    cweFamily: ['CWE-601'],
    dedupeFamily: 'open_redirect',
    owaspCategory: 'ssrf-redirects',
    label: 'open redirect',
    impact: 'An attacker-controlled redirect target sent users to an untrusted external origin.',
    remediation: 'Restrict redirect targets to relative paths or an explicit allowlist of trusted origins.',
  },
  {
    id: 'webhook_forgery',
    aliases: ['webhook_forgery', 'webhook_signature', 'hmac_bypass', 'signature_bypass'],
    canonicalCwe: 'CWE-345',
    cweFamily: ['CWE-345', 'CWE-347', 'CWE-287'],
    dedupeFamily: 'auth_bypass',
    owaspCategory: 'auth-identity',
    label: 'webhook signature forgery',
    impact: 'A webhook handler accepted an unsigned or forged payload without validating its cryptographic signature.',
    remediation: 'Verify webhook HMAC signatures in constant time over the raw request body using server-side secret material and enforce replay timestamps.',
  },
  {
    id: 'jwt_forgery',
    aliases: ['jwt_forgery', 'jwt', 'jwt_none', 'token_forgery'],
    canonicalCwe: 'CWE-347',
    cweFamily: ['CWE-347', 'CWE-287', 'CWE-345'],
    dedupeFamily: 'auth_bypass',
    owaspCategory: 'auth-identity',
    label: 'JWT / token forgery authentication bypass',
    impact: 'A forged or improperly verified authentication token bypassed authentication on a protected route.',
    remediation: 'Verify token signatures strictly against an explicit algorithm allowlist and server-controlled key material; reject alg=none and untrusted headers.',
  },
  {
    id: 'cryptographic_scope_replay',
    aliases: ['cryptographic_scope_replay'],
    canonicalCwe: 'CWE-347',
    cweFamily: ['CWE-347', 'CWE-287', 'CWE-345'],
    dedupeFamily: 'auth_bypass',
    owaspCategory: 'auth-identity',
    label: 'cryptographic scope replay / signature forgery',
    impact: 'A signed token or webhook signature was forged or replayed across tenant or scope boundaries.',
    remediation: 'Keep signing material strictly private and bind signatures to tenant, audience, and action scope.',
  },
  {
    id: 'auth_bypass',
    aliases: [
      'auth_bypass',
      'broken_auth',
      'broken_authentication',
      'weak_auth',
      'auth_protocol',
      'authentication_bypass',
      'mfa_bypass',
    ],
    canonicalCwe: 'CWE-287',
    cweFamily: [
      'CWE-287',
      'CWE-288',
      'CWE-290',
      'CWE-306',
      'CWE-307',
      'CWE-347',
      'CWE-345',
      'CWE-613',
      'CWE-384',
      'CWE-798',
    ],
    dedupeFamily: 'auth_bypass',
    owaspCategory: 'auth-identity',
    label: 'authentication bypass',
    impact: 'A crafted authentication header, token, or bypass parameter granted access to a route that denies unauthenticated callers.',
    remediation: 'Enforce server-side session/token verification uniformly and never trust client-supplied identity or bypass headers.',
  },
  {
    id: 'temporal_revocation',
    aliases: ['temporal_revocation', 'session_revocation', 'session_fixation', 'session_hijacking'],
    canonicalCwe: 'CWE-613',
    cweFamily: ['CWE-613', 'CWE-384', 'CWE-287'],
    dedupeFamily: 'session_revocation',
    owaspCategory: 'auth-identity',
    label: 'stale or revoked credential acceptance',
    impact: 'A revoked or demoted credential remained honored on a secondary surface after primary revocation.',
    remediation: 'Propagate session/token revocation synchronously across every primary, streaming, and async surface.',
  },
  {
    id: 'race_condition',
    aliases: [
      'race',
      'race_double_spend',
      'race_condition',
      'race_burst',
      'double_spend',
      'oversell',
      'inventory_oversell',
      'conserved_balance',
      'toctou',
    ],
    canonicalCwe: 'CWE-362',
    cweFamily: ['CWE-362', 'CWE-367', 'CWE-840'],
    dedupeFamily: 'race_condition',
    owaspCategory: 'business-logic-race',
    label: 'race condition',
    impact: 'A synchronized burst of the same request produced divergent outcomes (over-spend or duplicate effect).',
    remediation: 'Serialize the state transition (unique constraint, lock, or idempotency key).',
  },
  {
    id: 'price_tampering',
    aliases: ['price_tampering', 'price_manipulation'],
    canonicalCwe: 'CWE-472',
    cweFamily: ['CWE-472', 'CWE-840', 'CWE-841', 'CWE-1284'],
    dedupeFamily: 'business_logic',
    owaspCategory: 'business-logic-race',
    label: 'client-controlled price manipulation',
    impact: 'The server trusted a client-supplied price or amount instead of computing authoritative totals server-side.',
    remediation: 'Compute prices, discounts, and totals exclusively on the server from authoritative catalog state.',
  },
  {
    id: 'business_logic',
    aliases: [
      'business_logic',
      'invariant_violation',
      'workflow_skip',
      'workflow_bypass',
      'economic_conservation',
      'logic_flaw',
      'state_machine',
      'state_bypass',
      'payment_bypass',
      'limit_bypass',
      'quota_bypass',
      'coupon_abuse',
      'negative_quantity',
    ],
    canonicalCwe: 'CWE-840',
    cweFamily: ['CWE-840', 'CWE-841', 'CWE-472', 'CWE-1284', 'CWE-362', 'CWE-367'],
    dedupeFamily: 'business_logic',
    owaspCategory: 'business-logic-race',
    label: 'business-logic invariant violation',
    impact: 'A workflow or conservation invariant was violated by a multi-step sequence.',
    remediation: 'Enforce the invariant server-side atomically and re-validate workflow state on every transition.',
  },
  {
    id: 'info_disclosure',
    aliases: [
      'disclosure',
      'info_disclosure',
      'information_disclosure',
      'sensitive_data_exposure',
      'secret_disclosure',
      'secret_disclosed',
      'secret_leak',
      'data_exposure',
      'pii_exposure',
    ],
    canonicalCwe: 'CWE-200',
    cweFamily: ['CWE-200', 'CWE-209', 'CWE-359', 'CWE-522', 'CWE-532'],
    dedupeFamily: 'info_disclosure',
    owaspCategory: 'misconfig-exposure',
    label: 'information disclosure',
    impact: 'The response exposed data the requesting actor was not entitled to read.',
    remediation: 'Filter responses server-side to the fields the caller is authorized to see.',
  },
])

/**
 * Explicit narrow exceptions where a CWE accepted on an entry's receipt `cweFamily` MUST NOT
 * inherit that entry's `dedupeFamily`, preserving intentional cross-class vetoes in semantic
 * deduplication (e.g. keeping Mass Assignment CWE-915 disjoint from BOLA/BFLA CWE-285/CWE-863).
 */
export const DEDUPE_FAMILY_EXCEPTIONS: readonly DedupeFamilyException[] = Object.freeze([
  {
    entryId: 'mass_assignment',
    cwe: 'CWE-285',
    reason: 'Keep Mass Assignment (CWE-915) disjoint from BOLA/BFLA (CWE-285/CWE-639) in semantic dedupe so both bugs on the same mutation route stay separate.',
  },
  {
    entryId: 'mass_assignment',
    cwe: 'CWE-863',
    reason: 'Keep Mass Assignment (CWE-915) disjoint from BOLA/BFLA (CWE-863/CWE-639) in semantic dedupe so both bugs on the same mutation route stay separate.',
  },
])

function normalizeSnakeKey(raw: string): string {
  return raw.trim().toLowerCase().replace(/[\s/-]+/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '')
}

function normalizeKebabKey(raw: string): string {
  return raw.trim().toLowerCase().replace(/[\s_/]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '')
}

const TAXONOMY_BY_SNAKE_KEY: ReadonlyMap<string, VulnTaxonomyEntry> = (() => {
  const map = new Map<string, VulnTaxonomyEntry>()
  for (const entry of VULN_TAXONOMY) {
    map.set(normalizeSnakeKey(entry.id), entry)
    for (const alias of entry.aliases) {
      map.set(normalizeSnakeKey(alias), entry)
    }
  }
  return map
})()

/**
 * Canonical class -> OWASP coverage cell table derived directly from `VULN_TAXONOMY`
 * (kebab-case keys). Consumed by `src/server/coverage-category.ts` so coverage cells and
 * finding binding share a single authoritative mapping.
 */
export const CANONICAL_CLASS_TO_OWASP: Readonly<Record<string, OwaspCategory>> = (() => {
  const out: Record<string, OwaspCategory> = {}
  for (const entry of VULN_TAXONOMY) {
    out[normalizeKebabKey(entry.id)] = entry.owaspCategory
    for (const alias of entry.aliases) {
      out[normalizeKebabKey(alias)] = entry.owaspCategory
    }
  }
  return Object.freeze(out)
})()

const UNCLASSIFIED_CWE_FAMILY: ReceiptCweFamily = Object.freeze({
  cwe: UNCLASSIFIED_TAXONOMY_KEY,
  family: Object.freeze([]),
  category: UNCLASSIFIED_TAXONOMY_KEY,
  unclassified: true,
})

const UNCLASSIFIED_ATTRIBUTION: VulnProofAttribution = Object.freeze({
  label: 'unclassified finding',
  cwe: UNCLASSIFIED_TAXONOMY_KEY,
  category: UNCLASSIFIED_TAXONOMY_KEY,
  unclassified: true,
  impact: 'A verified security boundary violation occurred for a receipt class not yet mapped in the canonical taxonomy.',
  remediation: 'Review the verified transcript and classify this receipt class in src/vuln-taxonomy.ts before applying class-specific remediation.',
})

/** Resolve any receipt/finding vulnerability class label to its canonical taxonomy entry. */
export function lookupVulnTaxonomy(vulnClass: string | null | undefined): VulnTaxonomyEntry | null {
  if (!vulnClass || typeof vulnClass !== 'string') return null
  const key = normalizeSnakeKey(vulnClass)
  if (!key) return null
  return TAXONOMY_BY_SNAKE_KEY.get(key) ?? null
}

/**
 * Resolve a receipt `vulnClass` into its canonical CWE, accepted CWE family, and OWASP cell.
 * Unknown classes map explicitly to `'unclassified'` (never silently to `CWE-200`).
 */
export function cweFamilyFromTaxonomy(vulnClass: string): ReceiptCweFamily {
  const entry = lookupVulnTaxonomy(vulnClass)
  if (!entry) return UNCLASSIFIED_CWE_FAMILY
  return {
    cwe: entry.canonicalCwe,
    family: entry.cweFamily,
    category: entry.owaspCategory,
    unclassified: false,
  }
}

/**
 * Resolve reporting attribution for a confirmed proof receipt class from `VULN_TAXONOMY`.
 * Unknown classes stay visible as `'unclassified'` instead of silently reporting `CWE-200`.
 */
export function attributionFromTaxonomy(vulnClass: string): VulnProofAttribution {
  const entry = lookupVulnTaxonomy(vulnClass)
  if (!entry) return UNCLASSIFIED_ATTRIBUTION
  return {
    label: entry.label,
    cwe: entry.canonicalCwe,
    category: entry.owaspCategory,
    unclassified: false,
    impact: entry.impact,
    remediation: entry.remediation,
  }
}

const CONCRETE_CWE_RE = /^CWE-[1-9]\d{0,4}$/

/** True iff `value` is a concrete normalized `CWE-<digits>` identifier. */
export function isConcreteCwe(value: string | null | undefined): boolean {
  if (!value || typeof value !== 'string') return false
  return CONCRETE_CWE_RE.test(value.trim().toUpperCase())
}

const DEDUPE_EXCEPTION_KEYS: ReadonlySet<string> = new Set(
  DEDUPE_FAMILY_EXCEPTIONS.map(ex => `${ex.entryId}::${ex.cwe.trim().toUpperCase()}`),
)

/**
 * Semantic dedupe CWE-family membership derived strictly from `VULN_TAXONOMY` (minus explicit
 * `DEDUPE_FAMILY_EXCEPTIONS`). Single source of truth: no separate hand-maintained CWE family map.
 */
export const DEDUPE_CWE_FAMILIES_BY_CWE: ReadonlyMap<string, ReadonlySet<string>> = (() => {
  const map = new Map<string, Set<string>>()
  const add = (cwe: string, family: string) => {
    const norm = cwe.trim().toUpperCase()
    if (!CONCRETE_CWE_RE.test(norm)) return
    let set = map.get(norm)
    if (!set) {
      set = new Set<string>()
      map.set(norm, set)
    }
    set.add(family)
  }
  for (const entry of VULN_TAXONOMY) {
    add(entry.canonicalCwe, entry.dedupeFamily)
    for (const memberCwe of entry.cweFamily) {
      const norm = memberCwe.trim().toUpperCase()
      if (DEDUPE_EXCEPTION_KEYS.has(`${entry.id}::${norm}`)) continue
      add(norm, entry.dedupeFamily)
    }
  }
  return map
})()

/** Return the derived taxonomy dedupe family set for a CWE, or `null` if unlisted in `VULN_TAXONOMY`. */
export function dedupeCweFamiliesFor(cwe: string | null | undefined): ReadonlySet<string> | null {
  if (!cwe) return null
  const normalized = normalizeCwe(cwe)
  if (!isConcreteCwe(normalized)) return null
  return DEDUPE_CWE_FAMILIES_BY_CWE.get(normalized) ?? null
}

/**
 * True iff two concrete CWEs are identical or belong to intersecting derived taxonomy dedupe
 * families. Returns false if either CWE is unlisted/non-concrete or their families are disjoint.
 */
export function cweFamiliesIntersect(
  cweA: string | null | undefined,
  cweB: string | null | undefined,
): boolean {
  if (!cweA || !cweB) return false
  const normA = normalizeCwe(cweA)
  const normB = normalizeCwe(cweB)
  if (!isConcreteCwe(normA) || !isConcreteCwe(normB)) return false
  if (normA === normB) return true
  const famsA = DEDUPE_CWE_FAMILIES_BY_CWE.get(normA)
  const famsB = DEDUPE_CWE_FAMILIES_BY_CWE.get(normB)
  if (!famsA || !famsB) return false
  for (const fam of famsA) {
    if (famsB.has(fam)) return true
  }
  return false
}

/**
 * True iff BOTH CWEs are known taxonomy CWEs (`DEDUPE_CWE_FAMILIES_BY_CWE`) and belong to strictly
 * disjoint families. Unlisted CWEs (e.g. generic CWE-20) are NOT treated as conflicting singletons
 * so semantic dedupe never spuriously inflates finding counts for unmapped CWEs.
 */
export function cweFamiliesConflict(
  cweA: string | null | undefined,
  cweB: string | null | undefined,
): boolean {
  if (!cweA || !cweB) return false
  const normA = normalizeCwe(cweA)
  const normB = normalizeCwe(cweB)
  if (!isConcreteCwe(normA) || !isConcreteCwe(normB)) return false
  if (normA === normB) return false
  const famsA = DEDUPE_CWE_FAMILIES_BY_CWE.get(normA)
  const famsB = DEDUPE_CWE_FAMILIES_BY_CWE.get(normB)
  if (!famsA || !famsB) return false
  for (const fam of famsA) {
    if (famsB.has(fam)) return false
  }
  return true
}
