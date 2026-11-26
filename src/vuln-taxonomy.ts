/**
 * Single canonical vulnerability-class taxonomy (`R3-11`).
 *
 * Authoritative source of truth for:
 *   - receipt/finding class -> canonical CWE, accepted CWE family, OWASP coverage cell, and
 *     reporting attribution (`label`, `impact`, `remediation`);
 *   - canonical class -> OWASP coverage cell map shared with `src/server/coverage-category.ts`;
 *   - disjoint CWE-family equivalence classes enforced by the semantic deduplication veto in
 *     `src/server/dedupe.ts`.
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

/**
 * Frozen canonical vulnerability-class taxonomy table.
 * Derived consumers (`exec-verify.ts`, `coverage-category.ts`, `dedupe.ts`) MUST read from this
 * table rather than maintaining parallel regex ladders.
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
    cweFamily: ['CWE-89', 'CWE-564'],
    owaspCategory: 'injection-input',
    label: 'SQL injection',
    impact: 'Injected input changed the SQL query structure or timing of the server-side operation.',
    remediation: 'Use parameterized queries / prepared statements; never concatenate input into SQL.',
  },
  {
    id: 'nosqli',
    aliases: ['nosqli', 'nosql_injection'],
    canonicalCwe: 'CWE-943',
    cweFamily: ['CWE-943', 'CWE-74', 'CWE-89'],
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
    owaspCategory: 'injection-input',
    label: 'server-side template injection',
    impact: 'Untrusted input was evaluated by a server-side template engine.',
    remediation: 'Pass user input as template data rather than compiling it as template source; use a logic-less or sandboxed template context.',
  },
  {
    id: 'command_injection',
    aliases: ['command_injection', 'os_command_injection', 'cmdi', 'rce', 'code_injection', 'eval_injection'],
    canonicalCwe: 'CWE-78',
    cweFamily: ['CWE-78', 'CWE-77', 'CWE-94'],
    owaspCategory: 'injection-input',
    label: 'command injection',
    impact: 'Injected input altered a server-side OS command execution.',
    remediation: 'Pass arguments as an argv array without a shell and strictly allowlist dynamic parameters.',
  },
  {
    id: 'injection',
    aliases: ['injection', 'injection_input'],
    canonicalCwe: 'CWE-74',
    cweFamily: ['CWE-74', 'CWE-89', 'CWE-564', 'CWE-943', 'CWE-78', 'CWE-77', 'CWE-94', 'CWE-1336'],
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
      'cache',
    ],
    canonicalCwe: 'CWE-444',
    cweFamily: ['CWE-444', 'CWE-436', 'CWE-525'],
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
    owaspCategory: 'cors-client-side',
    label: 'cross-site request forgery',
    impact: 'A cross-site request performed a state change as the victim without a valid intent token.',
    remediation: 'Require a per-session anti-CSRF token (or SameSite=Lax cookies) on state-changing routes.',
  },
  {
    id: 'postmessage',
    aliases: ['postmessage'],
    canonicalCwe: 'CWE-346',
    cweFamily: ['CWE-346', 'CWE-345'],
    owaspCategory: 'cors-client-side',
    label: 'insecure postMessage origin validation',
    impact: 'A client-side postMessage handler trusted messages from an unverified origin.',
    remediation: 'Validate event.origin against an explicit allowlist before acting on postMessage payloads.',
  },
  {
    id: 'ssrf',
    aliases: ['ssrf', 'blind_ssrf', 'oob_ssrf', 'oob', 'server_side_request_forgery'],
    canonicalCwe: 'CWE-918',
    cweFamily: ['CWE-918'],
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
    owaspCategory: 'ssrf-redirects',
    label: 'open redirect',
    impact: 'An attacker-controlled redirect target sent users to an untrusted external origin.',
    remediation: 'Restrict redirect targets to relative paths or an explicit allowlist of trusted origins.',
  },
  {
    id: 'webhook_forgery',
    aliases: ['webhook_forgery', 'webhook', 'webhook_signature', 'hmac_bypass', 'signature_bypass'],
    canonicalCwe: 'CWE-345',
    cweFamily: ['CWE-345', 'CWE-347', 'CWE-287'],
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
      'auth',
      'authn',
      'authentication',
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
    owaspCategory: 'auth-identity',
    label: 'authentication bypass',
    impact: 'A crafted authentication header, token, or bypass parameter granted access to a route that denies unauthenticated callers.',
    remediation: 'Enforce server-side session/token verification uniformly and never trust client-supplied identity or bypass headers.',
  },
  {
    id: 'temporal_revocation',
    aliases: ['temporal_revocation', 'session_revocation', 'session_fixation', 'session_hijacking', 'session'],
    canonicalCwe: 'CWE-613',
    cweFamily: ['CWE-613', 'CWE-384', 'CWE-287'],
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
      'replay_attack',
      'rate_limit_bypass',
    ],
    canonicalCwe: 'CWE-840',
    cweFamily: ['CWE-840', 'CWE-841', 'CWE-472', 'CWE-1284', 'CWE-362', 'CWE-367'],
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
    owaspCategory: 'misconfig-exposure',
    label: 'information disclosure',
    impact: 'The response exposed data the requesting actor was not entitled to read.',
    remediation: 'Filter responses server-side to the fields the caller is authorized to see.',
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

/**
 * Disjoint CWE-family equivalence classes for semantic deduplication (`R3-11`).
 *
 * Distinct vulnerability classes that share an OWASP bucket (e.g. SQLi CWE-89 vs CMDi CWE-78 vs
 * SSTI CWE-1336 vs NoSQLi CWE-943 vs XXE CWE-611 inside `injection-input`, or BOLA CWE-639 vs
 * Mass Assignment CWE-915 inside `broken-access-control`) live in strictly disjoint families so
 * semantic deduplication can never silently collapse two distinct bugs on the same endpoint/param.
 */
export const DEDUPE_CWE_FAMILY_BY_CWE: Readonly<Record<string, string>> = Object.freeze({
  // Broken Access Control (object & function authorization)
  'CWE-639': 'authorization',
  'CWE-284': 'authorization',
  'CWE-285': 'authorization',
  'CWE-862': 'authorization',
  'CWE-863': 'authorization',
  'CWE-269': 'authorization',
  'CWE-566': 'authorization',
  'CWE-1220': 'authorization',
  // Mass assignment (distinct from BOLA/BFLA on the same mutation route)
  'CWE-915': 'mass_assignment',
  // Path traversal / file inclusion
  'CWE-22': 'path_traversal',
  'CWE-23': 'path_traversal',
  'CWE-73': 'path_traversal',
  // Injection subclasses — strictly separated so two injection bugs on one param never collapse
  'CWE-89': 'sqli',
  'CWE-564': 'sqli',
  'CWE-943': 'nosqli',
  'CWE-1336': 'ssti',
  'CWE-78': 'cmdi',
  'CWE-77': 'cmdi',
  'CWE-94': 'code_injection',
  'CWE-95': 'code_injection',
  'CWE-74': 'injection_generic',
  'CWE-611': 'xxe',
  'CWE-502': 'deserialization',
  'CWE-1321': 'prototype_pollution',
  'CWE-93': 'crlf_injection',
  'CWE-113': 'crlf_injection',
  'CWE-90': 'ldap_injection',
  'CWE-643': 'xpath_injection',
  // Parser / cache differential & request smuggling
  'CWE-444': 'parser_cache',
  'CWE-436': 'parser_cache',
  'CWE-525': 'parser_cache',
  // Client-side (XSS vs CSRF vs CORS vs headers vs cookies)
  'CWE-79': 'xss',
  'CWE-80': 'xss',
  'CWE-83': 'xss',
  'CWE-352': 'csrf',
  'CWE-942': 'cors',
  'CWE-346': 'cors',
  'CWE-693': 'security_headers',
  'CWE-1021': 'security_headers',
  'CWE-614': 'cookie_flags',
  'CWE-1004': 'cookie_flags',
  'CWE-1275': 'cookie_flags',
  // SSRF vs Open Redirect
  'CWE-918': 'ssrf',
  'CWE-601': 'open_redirect',
  // Authentication / cryptographic signature vs session revocation
  'CWE-287': 'auth_bypass',
  'CWE-288': 'auth_bypass',
  'CWE-290': 'auth_bypass',
  'CWE-306': 'auth_bypass',
  'CWE-307': 'auth_bypass',
  'CWE-345': 'auth_bypass',
  'CWE-347': 'auth_bypass',
  'CWE-798': 'auth_bypass',
  'CWE-613': 'session_revocation',
  'CWE-384': 'session_revocation',
  // Race condition vs business logic
  'CWE-362': 'race_condition',
  'CWE-367': 'race_condition',
  'CWE-840': 'business_logic',
  'CWE-841': 'business_logic',
  'CWE-472': 'business_logic',
  'CWE-1284': 'business_logic',
  // Transport & crypto
  'CWE-319': 'transport_crypto',
  'CWE-295': 'transport_crypto',
  'CWE-327': 'transport_crypto',
  // File upload
  'CWE-434': 'file_upload',
  // Information disclosure
  'CWE-200': 'info_disclosure',
  'CWE-209': 'info_disclosure',
  'CWE-359': 'info_disclosure',
  'CWE-522': 'info_disclosure',
  'CWE-532': 'info_disclosure',
})

/** Resolve a concrete CWE identifier to its canonical dedupe family (or itself as a singleton). */
export function cweDedupeFamily(cwe: string | null | undefined): string | null {
  if (!cwe) return null
  const normalized = normalizeCwe(cwe)
  if (!isConcreteCwe(normalized)) return null
  return DEDUPE_CWE_FAMILY_BY_CWE[normalized] ?? normalized
}

/**
 * True iff two concrete CWEs belong to intersecting dedupe families (same concrete CWE or same
 * canonical dedupe family). Returns false if either CWE is non-concrete or their families conflict.
 */
export function cweFamiliesIntersect(
  cweA: string | null | undefined,
  cweB: string | null | undefined,
): boolean {
  const famA = cweDedupeFamily(cweA)
  const famB = cweDedupeFamily(cweB)
  if (!famA || !famB) return false
  return famA === famB
}
