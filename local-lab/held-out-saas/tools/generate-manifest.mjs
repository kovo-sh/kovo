// One-off generator for manifest.json and patches/*.patch (run from the lab directory root).
import { randomBytes } from 'node:crypto'
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const labDir = process.argv[2]
const manifestPath = join(labDir, 'manifest.json')
const prior = existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, 'utf8')) : null
const priorMarkers = new Map((prior?.challenges ?? []).map(c => [c.id, c.flagMarker]))
const hex = () => randomBytes(4).toString('hex')

const V = (n, o) => ({
  id: `hos-${String(n).padStart(2, '0')}`,
  ...o,
})

const vulns = [
  V(1, { name: 'Multi-tenant BOLA on invoices (REST)', vulnClass: 'bola', cwe: 'CWE-639', endpoint: '/api/v1/invoices/{id}', method: 'GET', param: 'id', encoding: 'path', expectedReplayKind: 'http_chain', probeClass: 'authz_matrix', tierRequired: 1, requiresAuth: true, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'persona_matrix', severity: 'high', surfaceHint: 'openapi', personas: ['persona_a', 'persona_b'], evidence: 'persona_b (globex) reads persona_a-visible invoice ids of other tenants; response carries the marker' }),
  V(2, { name: 'GraphQL nested resolver BOLA (User.invoices)', vulnClass: 'graphql_bola', cwe: 'CWE-639', endpoint: '/graphql', method: 'POST', param: 'user.invoices', encoding: 'graphql_var', expectedReplayKind: 'http_chain', probeClass: 'graphql_audit', tierRequired: 1, requiresAuth: true, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'graphql_audit', severity: 'high', surfaceHint: 'js_bundle+introspection', personas: ['persona_a', 'persona_b'], evidence: 'user(id){ invoices { memo } } returns another tenant\'s invoices' }),
  V(3, { name: 'BFLA: feature-flag admin action callable by any role', vulnClass: 'bfla', cwe: 'CWE-285', endpoint: '/api/v1/admin/feature-flags', method: 'POST', param: 'flag', encoding: 'json', expectedReplayKind: 'http_chain', probeClass: 'authz_matrix', tierRequired: 2, requiresAuth: true, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'persona_matrix', severity: 'high', surfaceHint: 'openapi', personas: ['viewer', 'admin'], evidence: 'viewer toggles a flag that only admin may toggle (GET is correctly 403)' }),
  V(4, { name: 'Mass assignment on profile (role / creditLimit)', vulnClass: 'mass_assignment', cwe: 'CWE-915', endpoint: '/api/v1/profile', method: 'PATCH', param: 'role', encoding: 'json', expectedReplayKind: 'http_chain', probeClass: 'mass_assignment', tierRequired: 2, requiresAuth: true, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'jwt_auth_mutation', severity: 'high', surfaceHint: 'openapi', personas: ['persona_a'], evidence: 'PATCH {role:"admin"} then GET /api/v1/profile shows role admin + adminConsoleToken' }),
  V(5, { name: 'Next.js Server Action authorization bypass (updateOrgPlan)', vulnClass: 'server_action_authz', cwe: 'CWE-862', endpoint: '/_actions/updateOrgPlan', method: 'POST', param: 'plan', encoding: 'json', expectedReplayKind: 'http_chain', probeClass: 'authz_matrix', tierRequired: 2, requiresAuth: false, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'server_action_rpc', severity: 'critical', surfaceHint: 'js_bundle (createServerReference / Next-Action)', personas: ['persona_b'], evidence: 'unauthenticated or cross-tenant call changes any org plan; GET /api/v1/org reflects it' }),
  V(6, { name: 'SQL injection (query string, boolean)', vulnClass: 'sqli_boolean', cwe: 'CWE-89', endpoint: '/api/v1/sales-orders', method: 'GET', param: 'ref', encoding: 'query', expectedReplayKind: 'sql_boolean_diff', probeClass: 'sqli_boolean', tierRequired: 1, requiresAuth: true, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'universal_encodings', severity: 'high', surfaceHint: 'openapi', personas: ['persona_a'], evidence: 'ref=1\' AND k=k-- - vs k=k+1 diverge (sqlite dialect)' }),
  V(7, { name: 'SQL injection behind CSRF-protected HTML form', vulnClass: 'sqli_form_csrf', cwe: 'CWE-89', endpoint: '/app/members/search', method: 'POST', param: 'member_id', encoding: 'form', expectedReplayKind: 'sql_boolean_diff', probeClass: 'sqli_boolean', tierRequired: 2, requiresAuth: true, requiresCsrf: true, requiresBrowser: false, requiresV4Feature: 'csrf_bind', severity: 'high', surfaceHint: 'html_form (landing page + /app/members)', personas: ['persona_a'], evidence: 'double-submit csrf_token cookie + _csrf hidden field required; member_id injectable' }),
  V(8, { name: 'Blind time-based SQL injection (JSON filter)', vulnClass: 'sqli_time_blind', cwe: 'CWE-89', endpoint: '/api/v1/analytics/query', method: 'POST', param: 'filter.name', encoding: 'json', expectedReplayKind: 'sql_time_diff', probeClass: 'sqli_time_diff', tierRequired: 3, requiresAuth: true, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'sqli_time_diff', severity: 'high', surfaceHint: 'js_bundle', personas: ['persona_a'], dialect: 'sqlite', evidence: 'response body is constant; only latency differs (SQLite RANDOMBLOB / SLEEP delay)' }),
  V(9, { name: 'GraphQL scalar-argument SQL injection (products.sku)', vulnClass: 'graphql_sqli', cwe: 'CWE-89', endpoint: '/graphql', method: 'POST', param: 'sku', encoding: 'graphql_var', expectedReplayKind: 'sql_boolean_diff', probeClass: 'sqli_boolean', tierRequired: 1, requiresAuth: true, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'graphql_audit', severity: 'high', surfaceHint: 'js_bundle+introspection', personas: ['persona_a'], evidence: 'variables.sku injected into WHERE sku = \'...\'; boolean differential on products list' }),
  V(10, { name: 'XML external entity injection in catalog import', vulnClass: 'xxe', cwe: 'CWE-611', endpoint: '/api/v1/import/xml', method: 'POST', param: 'xml', encoding: 'xml', expectedReplayKind: 'http_chain', probeClass: 'xxe_canary', tierRequired: 2, requiresAuth: false, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'xml_encoding', severity: 'high', surfaceHint: 'js_bundle', personas: [], evidence: 'inline file:/// entity (virtual FS) and OOB http entity limited to loopback' }),
  V(11, { name: 'JWT acceptance of alg:none / stripped signature', vulnClass: 'jwt_alg_none', cwe: 'CWE-347', endpoint: '/api/v1/session', method: 'GET', param: 'Authorization', encoding: 'jwt', expectedReplayKind: 'auth_protocol_proof', probeClass: 'auth_protocol_audit', tierRequired: 2, requiresAuth: true, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'jwt_auth_mutation', severity: 'critical', surfaceHint: 'openapi', personas: ['persona_a'], authMutations: ['alg_none', 'strip_signature', 'claim_swap'], evidence: 'tampered signatures are rejected (401) but alg:none and empty signatures are accepted' }),
  V(12, { name: 'JWT jku header trusted (key-set fetch / OOB callback)', vulnClass: 'jwt_jku', cwe: 'CWE-347', endpoint: '/api/v1/partner/ledger', method: 'GET', param: 'Authorization', encoding: 'jwt', expectedReplayKind: 'auth_protocol_proof', probeClass: 'auth_protocol_audit', tierRequired: 2, requiresAuth: true, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'jwt_auth_mutation', severity: 'high', surfaceHint: 'js_bundle', personas: ['persona_a'], authMutations: ['jku_x5u_canary'], evidence: 'server fetches the jku URL (loopback canary only) while verifying the token' }),
  V(13, { name: 'Checkout workflow step-skip (draft -> confirm without payment)', vulnClass: 'workflow_skip', cwe: 'CWE-841', endpoint: '/api/v1/checkout/orders/{id}/confirm', method: 'POST', param: 'id', encoding: 'path', expectedReplayKind: 'http_chain', probeClass: 'workflow_invariant', tierRequired: 2, requiresAuth: true, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'stateful_session', severity: 'high', surfaceHint: 'openapi', personas: ['persona_a'], evidence: 'order created as draft is confirmed (licenseKey issued) while paid=false' }),
  V(14, { name: 'Voucher / credit double-spend race', vulnClass: 'race_condition', cwe: 'CWE-362', endpoint: '/api/v1/credits/redeem', method: 'POST', param: 'code', encoding: 'json', expectedReplayKind: 'race_burst', probeClass: 'race_burst', tierRequired: 2, requiresAuth: true, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'race_burst', severity: 'high', surfaceHint: 'openapi', personas: ['persona_a'], evidence: 'burst of N redeems of one single-use voucher credits multiple times (balance > start + value)' }),
  V(15, { name: 'Second-order stored XSS (comment -> activity feed)', vulnClass: 'second_order_xss', cwe: 'CWE-79', endpoint: '/api/v1/comments', method: 'POST', param: 'body', encoding: 'json', expectedReplayKind: 'browser_dom', probeClass: 'xss_context', tierRequired: 2, requiresAuth: true, requiresCsrf: false, requiresBrowser: true, requiresV4Feature: 'second_order_canary', severity: 'high', surfaceHint: 'openapi', surfacedAt: '/app/projects/{id}/activity', personas: ['persona_a', 'admin'], evidence: 'marker stored through the API surfaces unescaped on the HTML activity page' }),
  V(16, { name: 'Second-order SSRF via webhook registration + delivery', vulnClass: 'second_order_ssrf', cwe: 'CWE-918', endpoint: '/api/v1/webhooks', method: 'POST', param: 'url', encoding: 'json', expectedReplayKind: 'http_chain', probeClass: 'ssrf_canary', tierRequired: 2, requiresAuth: true, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'second_order_canary', severity: 'high', surfaceHint: 'js_bundle', surfacedAt: '/api/v1/webhooks/{id}/ping', personas: ['persona_a'], evidence: 'registered URL is fetched later by the delivery agent (loopback / canary only)' }),
  V(17, { name: 'Web cache deception on account page', vulnClass: 'cache_deception', cwe: 'CWE-524', endpoint: '/app/account/{path}', method: 'GET', param: 'path', encoding: 'cache', expectedReplayKind: 'cache_differential', probeClass: 'cache_poison_deception', tierRequired: 2, requiresAuth: true, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'cache_buster', severity: 'high', surfaceHint: 'html_link', personas: ['persona_a'], evidence: '/app/account/x.css?_gcb=<uuid> as persona caches the private page; anonymous verify with same _gcb gets a HIT' }),
  V(18, { name: 'DOM-based XSS in search page', vulnClass: 'dom_xss', cwe: 'CWE-79', endpoint: '/app/search', method: 'GET', param: 'q', encoding: 'browser', expectedReplayKind: 'browser_dom', probeClass: 'browser_chain', tierRequired: 2, requiresAuth: false, requiresCsrf: false, requiresBrowser: true, requiresV4Feature: 'persistent_browser', severity: 'medium', surfaceHint: 'html_form + /static/search.js', personas: [], evidence: 'location.search flows into innerHTML in /static/search.js (server never reflects q)' }),
  V(19, { name: 'Server-side template injection in notification preview', vulnClass: 'ssti', cwe: 'CWE-1336', endpoint: '/api/v1/notifications/preview', method: 'POST', param: 'template', encoding: 'json', expectedReplayKind: 'http_chain', probeClass: 'ssti_math', tierRequired: 2, requiresAuth: true, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'universal_encodings', severity: 'high', surfaceHint: 'openapi', personas: ['persona_a'], evidence: '{{a*b}} / ${a*b} evaluated server-side (closed arithmetic interpreter, no host code execution)' }),
  V(20, { name: 'Path traversal in export download (virtual FS)', vulnClass: 'path_traversal', cwe: 'CWE-22', endpoint: '/api/v1/exports/download', method: 'GET', param: 'file', encoding: 'query', expectedReplayKind: 'http_chain', probeClass: 'path_traversal', tierRequired: 1, requiresAuth: true, requiresCsrf: false, requiresBrowser: false, requiresV4Feature: 'universal_encodings', severity: 'high', surfaceHint: 'openapi', personas: ['persona_a'], evidence: 'file=../../etc/passwd resolves inside the lab virtual FS only (never the host FS)' }),
]

const D = (n, o) => ({ id: `hos-d${n}`, isDecoy: true, requiresCsrf: false, requiresBrowser: false, tierRequired: 1, ...o })
const decoys = [
  D(1, { name: 'Parameterised catalog search (SQLi look-alike)', vulnClass: 'decoy_sqli', cwe: 'CWE-89', endpoint: '/api/v1/catalog/search', method: 'GET', param: 'q', encoding: 'query', requiresAuth: true, decoyReason: 'Uses prepared statements; quotes and comment markers are inert data so boolean/time differentials never diverge.' }),
  D(2, { name: 'Tenant-scoped v2 invoices (BOLA look-alike)', vulnClass: 'decoy_bola', cwe: 'CWE-639', endpoint: '/api/v2/invoices/{id}', method: 'GET', param: 'id', encoding: 'path', requiresAuth: true, decoyReason: 'Enforces tenant ownership and answers 403 for cross-tenant ids, so the authz matrix shows correct denial.' }),
  D(3, { name: 'HTML-escaped project notes (stored XSS look-alike)', vulnClass: 'decoy_xss', cwe: 'CWE-79', endpoint: '/api/v1/notes', method: 'POST', param: 'body', encoding: 'json', requiresAuth: true, surfacedAt: '/app/projects/{id}/notes', decoyReason: 'Notes are HTML-escaped on every render path, so injected markup is shown as inert text.' }),
  D(4, { name: 'Strict HS256 session verifier (JWT look-alike)', vulnClass: 'decoy_jwt', cwe: 'CWE-347', endpoint: '/api/v2/session', method: 'GET', param: 'Authorization', encoding: 'jwt', requiresAuth: true, decoyReason: 'Requires exact alg HS256 with a verified signature, so alg none, stripped, tampered or jku/kid tokens are rejected.' }),
  D(5, { name: 'DTD-disabled XML importer (XXE look-alike)', vulnClass: 'decoy_xxe', cwe: 'CWE-611', endpoint: '/api/v1/import/xml/strict', method: 'POST', param: 'xml', encoding: 'xml', requiresAuth: false, decoyReason: 'DOCTYPE declarations are rejected outright; entities are never expanded and no external fetch happens.' }),
  D(6, { name: 'Public static plan catalog with Cache-Control: public (cache deception look-alike)', vulnClass: 'decoy_cache', cwe: 'CWE-524', endpoint: '/public/catalog/{name}', method: 'GET', param: 'name', encoding: 'cache', requiresAuth: false, decoyReason: 'Serves identical non-sensitive public data to every caller; a public cache entry exposes nothing user-specific.' }),
]

for (const c of vulns) c.flagMarker = priorMarkers.get(c.id) ?? `HOSFLAG-${c.id.slice(4)}-${hex()}`
for (const c of vulns) c.patchId = c.id

const manifest = {
  schemaVersion: 1,
  suite: 'held-out-saas',
  name: 'Orbit Workspace — Held-Out Modern SaaS Lab',
  description: '20 planted High/Critical vulns + 6 hard decoys across a multi-tenant SaaS (REST, GraphQL, server actions, XML import, webhooks, edge cache). Synthetic data only; all SSRF/XXE/JKU egress is restricted to loopback.',
  lab: {
    directory: 'local-lab/held-out-saas',
    dockerComposeFile: 'docker-compose.yml',
    healthPath: '/health',
    internalPort: 3000,
    inProcessEntry: 'server.ts',
    startFunction: 'startHeldOutSaasServer',
    sqlDialect: 'sqlite',
    patchDirectory: 'patches',
  },
  personas: {
    persona_a: { userId: 'u_acme_1', tenantId: 'acme', role: 'member', authKind: 'bearer' },
    persona_b: { userId: 'u_globex_1', tenantId: 'globex', role: 'member', authKind: 'bearer' },
    admin: { userId: 'u_acme_admin', tenantId: 'acme', role: 'admin', authKind: 'bearer' },
    viewer: { userId: 'u_acme_viewer', tenantId: 'acme', role: 'viewer', authKind: 'bearer' },
  },
  challenges: [...vulns, ...decoys],
}
writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)

// ---- patches: each flips exactly one switch line in src/config.mjs (zero-context unified diff) ------------------
const configPath = 'src/config.mjs'
const lines = readFileSync(join(labDir, configPath), 'utf8').split('\n')
mkdirSync(join(labDir, 'patches'), { recursive: true })
const index = []
for (const c of vulns) {
  const needle = `  '${c.id}': false,`
  const n = lines.indexOf(needle) + 1
  if (n === 0) throw new Error(`switch for ${c.id} not found`)
  const diff = `--- a/${configPath}\n+++ b/${configPath}\n@@ -${n},1 +${n},1 @@\n-${needle}\n+  '${c.id}': true,\n`
  writeFileSync(join(labDir, 'patches', `${c.id}.patch`), diff)
  index.push({ patchId: c.id, file: `patches/${c.id}.patch`, fixes: c.name, cwe: c.cwe })
}
writeFileSync(join(labDir, 'patches', 'index.json'), `${JSON.stringify({ patches: index }, null, 2)}\n`)
console.log(`manifest: ${vulns.length} vulns + ${decoys.length} decoys; patches: ${index.length}`)
