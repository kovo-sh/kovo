/**
 * R2-15 (`cq-12a`): Read-Only Taxonomy Conformance Ratchet & Typed-First Classification Suite.
 *
 * Cross-checks all live vulnerability taxonomy tables read-only without introducing a single-source
 * refactor yet (`cq-10` remains decoupled):
 *   - `CWE_TO_RECEIPT_CLASS` (`src/server/floor-recipe-engine.ts`)
 *   - `SEVERITY_BY_CLASS` (`src/server/floor-recipe-engine.ts`)
 *   - `IMPACT_CLASS_CWES` (`src/server/oracle-invariants.ts`)
 *   - `cweFamilyForReceiptClass` (`src/server/exec-verify.ts`)
 *   - `inferInjectionFamily` (`src/server/verify-claims.ts`)
 *   - `categoryToOwaspCoverageCategory` (`src/server/coverage-category.ts`)
 *   - grader `classKey` (`benchmarks/realistic-bench/grader/match.ts`)
 *
 * Enforces:
 *   1. Cross-table taxonomy disagreements are strictly non-increasing (shrinking ratchet).
 *   2. `CWE-(?:...)` regex alternation sites across `src/` are strictly non-increasing.
 *   3. Every deterministic floor spec classifies strictly typed-first (`classifyImpactDescriptor`
 *      and `classifyBoundaryClaim`), specifically ensuring XXE, SSRF, path traversal, and JWT
 *      never relabel to `'authorization'` even if poisoned with legacy authorization prose.
 *   4. Per-class floor `baseFields` impact/remediation templates carry class-specific guidance
 *      without authorization boilerplate and preserve endpoint-bearing `title` verbatim.
 *   5. `inferInjectionFamily` is typed-first, fails closed to the typed family when prose
 *      disagrees, and fails closed to `'ambiguous'` (never `null` any-family widening) when
 *      untyped prose conflicts across multiple families.
 *   6. `bindConfirmedFindingIdentity` derives consistent class severity bands (`open_redirect`
 *      -> `'medium'`) and `IMMUTABLE_CONFIRMED_FINDING_FIELDS` includes `'severity'`.
 */
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { classKey } from '../benchmarks/realistic-bench/grader/match.ts'
import type { Finding } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { categoryToOwaspCoverageCategory } from '../src/server/coverage-category.ts'
import { baseFields, type Severity } from '../src/server/deterministic-specs.ts'
import {
  IMMUTABLE_CONFIRMED_FINDING_FIELDS,
  agentProofAttribution,
  bindConfirmedFindingIdentity,
  cweFamilyForReceiptClass,
  deriveSeverityBandForClass,
  isCweConsistentWithReceiptClass,
  isSensitiveRepoEntry as execVerifyIsSensitiveRepoEntry,
  isSensitiveRepoRelativePath as execVerifyIsSensitiveRepoRelativePath,
} from '../src/server/exec-verify.ts'
import { CWE_TO_RECEIPT_CLASS, SEVERITY_BY_CLASS, receiptVulnClassFor } from '../src/server/floor-recipe-engine.ts'
import {
  IMPACT_CLASS_CWES,
  classifyBoundaryClaim,
  classifyImpactDescriptor,
  injectionFamilyFromTyped,
  matchStrippedInjectionFingerprint,
  type BoundaryClass,
  type ImpactClass,
  type ImpactStep,
  type InjectionFamily,
} from '../src/server/oracle-invariants.ts'
import {
  isSensitiveRepoEntry as safetyIsSensitiveRepoEntry,
  isSensitiveRepoRelativePath as safetyIsSensitiveRepoRelativePath,
} from '../src/server/safety-primitives.ts'
import { REGISTERED_V8_ORACLE_FAMILIES } from '../src/server/terminal-oracle-registry.ts'
import { inferInjectionFamily } from '../src/server/verify-claims.ts'
import {
  CANONICAL_CLASS_TO_OWASP,
  DEDUPE_FAMILY_EXCEPTIONS,
  UNCLASSIFIED_TAXONOMY_KEY,
  VULN_TAXONOMY,
  cweFamiliesIntersect,
  lookupVulnTaxonomy,
} from '../src/vuln-taxonomy.ts'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

/**
 * Baselined cross-table taxonomy disagreements (shrunk from 41 -> 14 in R3-11).
 * All 12 `owasp-vs-exec-verify` disagreements and 15 `exec-verify-missing` disagreements were
 * eliminated by unifying `exec-verify.ts` and `coverage-category.ts` on `src/vuln-taxonomy.ts`.
 * Generic `injection` intentionally keeps a tight `['CWE-74']` family (F1 drift-gate invariant);
 * the remaining 14 entries live in `floor-recipe-engine.ts` / `oracle-invariants.ts` (scheduled
 * for R3-13 registry unification). Entries may only be removed, never added.
 */
const KNOWN_TAXONOMY_DISAGREEMENTS: ReadonlySet<string> = new Set([
  'exec-verify-missing:CWE-1021:in:bola',
  'exec-verify-missing:CWE-362:in:bola',
  'exec-verify-missing:CWE-564:in:injection',
  'exec-verify-missing:CWE-89:in:injection',
  'exec-verify-missing:CWE-943:in:injection',
  'grader-vs-receipt:CWE-284:bfla!=bola',
  'grader-vs-receipt:CWE-362:race_condition!=bola',
  'grader-vs-receipt:CWE-566:bfla!=bola',
  'impact-cwes-missing:CWE-1021:in:bola',
  'impact-cwes-missing:CWE-1220:in:bola',
  'impact-cwes-missing:CWE-1284:in:business_logic',
  'impact-cwes-missing:CWE-284:in:bola',
  'impact-cwes-missing:CWE-362:in:bola',
  'impact-cwes-missing:CWE-566:in:bola',
])

const IMPACT_CLASS_TO_RECEIPT_CLASS: Readonly<Record<string, string>> = {
  bola: 'bola',
  mass_assignment: 'mass_assignment',
  csrf: 'csrf',
  markup: 'xss_stored',
  disclosure: 'info_disclosure',
  business_logic: 'business_logic',
  injection: 'injection',
}

function collectCrossTableDisagreements(): string[] {
  const disagreements: string[] = []

  // 1. CWE_TO_RECEIPT_CLASS vs grader `classKey` & exec-verify `cweFamilyForReceiptClass`
  for (const [cweStr, receiptClass] of Object.entries(CWE_TO_RECEIPT_CLASS)) {
    const cwe = `CWE-${Number(cweStr)}`
    const graderKey = classKey({ cwe })
    if (graderKey && graderKey !== receiptClass) {
      disagreements.push(`grader-vs-receipt:${cwe}:${graderKey}!=${receiptClass}`)
    }
    const execFamily = cweFamilyForReceiptClass(receiptClass)
    if (!execFamily.family.includes(cwe)) {
      disagreements.push(`exec-verify-missing:${cwe}:in:${receiptClass}`)
    }
  }

  // 2. IMPACT_CLASS_CWES vs CWE_TO_RECEIPT_CLASS bidirectional parity
  for (const [impactClass, receiptClass] of Object.entries(IMPACT_CLASS_TO_RECEIPT_CLASS)) {
    const impactSet = new Set(IMPACT_CLASS_CWES[impactClass] ?? [])
    const receiptCwes = Object.entries(CWE_TO_RECEIPT_CLASS)
      .filter(([, cls]) => cls === receiptClass)
      .map(([cweStr]) => Number(cweStr))
    for (const cweNum of receiptCwes) {
      if (!impactSet.has(cweNum)) {
        disagreements.push(`impact-cwes-missing:CWE-${cweNum}:in:${impactClass}`)
      }
    }
    for (const cweNum of impactSet) {
      if (CWE_TO_RECEIPT_CLASS[cweNum] !== receiptClass) {
        disagreements.push(`receipt-map-missing:CWE-${cweNum}:for:${impactClass}`)
      }
    }
  }

  // 3. Injection CWEs in CWE_TO_RECEIPT_CLASS / IMPACT_CLASS_CWES vs `inferInjectionFamily`
  for (const cweNum of IMPACT_CLASS_CWES.injection ?? []) {
    const cwe = `CWE-${cweNum}`
    const inferred = inferInjectionFamily({ cwe }, [])
    if (!inferred || inferred === 'ambiguous') {
      disagreements.push(`infer-injection-missing:${cwe}`)
    }
  }

  // 4. OWASP coverage category projection vs exec-verify category
  const distinctClasses = [
    ...new Set([...Object.values(CWE_TO_RECEIPT_CLASS), ...Object.keys(SEVERITY_BY_CLASS)]),
  ].sort()
  for (const cls of distinctClasses) {
    const owasp = categoryToOwaspCoverageCategory(cls)
    assert.ok(owasp, `every taxonomy class must map to a canonical OWASP coverage category: ${cls}`)
    const execCat = cweFamilyForReceiptClass(cls).category
    if (execCat !== owasp) {
      disagreements.push(`owasp-vs-exec-verify:${cls}:${owasp}!=${execCat}`)
    }
  }

  return disagreements.sort()
}

function collectSourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist') continue
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      out.push(...collectSourceFiles(full))
    } else if (entry.isFile() && /\.(?:ts|tsx|mts|cts)$/.test(entry.name) && !/\.(?:test|spec)\./.test(entry.name)) {
      out.push(full)
    }
  }
  return out
}

test('R2-15 ratchet: cross-table taxonomy disagreements never increase and no new drift appears', () => {
  const observed = collectCrossTableDisagreements()
  const unexpected = observed.filter(item => !KNOWN_TAXONOMY_DISAGREEMENTS.has(item))
  assert.deepEqual(
    unexpected,
    [],
    `new cross-table taxonomy disagreement(s) introduced: ${unexpected.join(', ')}`,
  )
  assert.ok(
    observed.length <= KNOWN_TAXONOMY_DISAGREEMENTS.size,
    `taxonomy disagreement count must never grow (got ${observed.length}, ceiling ${KNOWN_TAXONOMY_DISAGREEMENTS.size})`,
  )
})

test('R2-15 ratchet: CWE-(?:...) regex alternation sites across src/ stay strictly non-increasing', () => {
  const ALLOWED_CWE_ALT_FILES = new Set([
    'src/server/floor-recipe-engine.ts',
    'src/server/oracle-invariants.ts',
  ])
  const srcFiles = collectSourceFiles(join(REPO_ROOT, 'src'))
  let totalSites = 0
  const filesWithSites = new Set<string>()
  for (const absPath of srcFiles) {
    const text = readFileSync(absPath, 'utf8')
    const matches = text.match(/CWE-\(\?:/g)
    if (!matches?.length) continue
    const rel = relative(REPO_ROOT, absPath).replace(/\\/g, '/')
    filesWithSites.add(rel)
    totalSites += matches.length
    assert.ok(
      ALLOWED_CWE_ALT_FILES.has(rel),
      `new CWE-(?:...) alternation file added outside ratchet baseline: ${rel}`,
    )
  }
  assert.ok(
    totalSites <= 10,
    `CWE-(?:...) alternation count must not exceed 10 (reduced from 13 in R2-15; got ${totalSites})`,
  )
  assert.ok(
    filesWithSites.size <= 2,
    `CWE-(?:...) alternation file count must not exceed 2 (reduced from 3 in R2-15; got ${filesWithSites.size})`,
  )
})

interface FloorSpecDescriptorCase {
  name: string
  vulnClass: string
  cwe: string
  category: string
  title: string
  severity: Severity
  expectedImpact: ImpactClass
  expectedBoundary: BoundaryClass
  expectedInjectionFamily: InjectionFamily | null
  expectedReceiptClass?: string | null
}

const FLOOR_SPEC_CASES: readonly FloorSpecDescriptorCase[] = [
  {
    name: 'xxe-oob',
    vulnClass: 'xxe',
    cwe: 'CWE-611',
    category: 'xxe',
    title: 'XML external entity injection (out-of-band callback) on /api/xml',
    severity: 'high',
    expectedImpact: 'other',
    expectedBoundary: 'other',
    expectedInjectionFamily: 'xxe',
    expectedReceiptClass: 'xxe',
  },
  {
    name: 'ssrf-oob',
    vulnClass: 'ssrf',
    cwe: 'CWE-918',
    category: 'ssrf',
    title: 'Server-side request forgery (out-of-band callback) on /api/fetch',
    severity: 'high',
    expectedImpact: 'other',
    expectedBoundary: 'other',
    expectedInjectionFamily: null,
    expectedReceiptClass: 'ssrf',
  },
  {
    name: 'ssrf-second-order',
    vulnClass: 'ssrf',
    cwe: 'CWE-918',
    category: 'ssrf',
    title: 'Second-order server-side request forgery (stored URL fetched later)',
    severity: 'high',
    expectedImpact: 'other',
    expectedBoundary: 'other',
    expectedInjectionFamily: null,
    expectedReceiptClass: 'ssrf',
  },
  {
    name: 'path-traversal',
    vulnClass: 'path_traversal',
    cwe: 'CWE-22',
    category: 'path-traversal',
    title: 'Path traversal escapes the served root (jail-escape read) on /api/files',
    severity: 'high',
    expectedImpact: 'other',
    expectedBoundary: 'other',
    expectedInjectionFamily: 'traversal',
    expectedReceiptClass: null,
  },
  {
    name: 'jwt-unsigned',
    vulnClass: 'jwt',
    cwe: 'CWE-347',
    category: 'jwt',
    title: 'JWT signature verification bypass (unsigned token accepted) on /api/me',
    severity: 'high',
    expectedImpact: 'other',
    expectedBoundary: 'auth',
    expectedInjectionFamily: null,
    expectedReceiptClass: 'auth_bypass',
  },
  {
    name: 'webhook-bypass',
    vulnClass: 'webhook_forgery',
    cwe: 'CWE-345',
    category: 'webhook',
    title: 'Webhook signature verification bypass on /api/webhooks/billing',
    severity: 'high',
    expectedImpact: 'other',
    expectedBoundary: 'other',
    expectedInjectionFamily: null,
    expectedReceiptClass: 'webhook_forgery',
  },
  {
    name: 'open-redirect',
    vulnClass: 'open_redirect',
    cwe: 'CWE-601',
    category: 'open-redirect',
    title: 'Unvalidated redirect target (off-origin navigation) on /redirect',
    severity: 'medium',
    expectedImpact: 'other',
    expectedBoundary: 'other',
    expectedInjectionFamily: null,
    expectedReceiptClass: 'open_redirect',
  },
  {
    name: 'sqli-boolean',
    vulnClass: 'sqli',
    cwe: 'CWE-89',
    category: 'injection-input',
    title: 'Boolean-based SQL injection differential on /api/search',
    severity: 'high',
    expectedImpact: 'injection',
    expectedBoundary: 'other',
    expectedInjectionFamily: 'sqli',
    expectedReceiptClass: 'injection',
  },
  {
    name: 'ssti-math',
    vulnClass: 'ssti',
    cwe: 'CWE-1336',
    category: 'injection-input',
    title: 'Server-side template injection (arithmetic evaluation) on /api/render',
    severity: 'high',
    expectedImpact: 'injection',
    expectedBoundary: 'other',
    expectedInjectionFamily: 'ssti',
    expectedReceiptClass: null,
  },
  {
    name: 'cmdi-echo',
    vulnClass: 'command_injection',
    cwe: 'CWE-78',
    category: 'injection-input',
    title: 'Command injection via shell metacharacters (nonce echo proof) on /api/ping',
    severity: 'critical',
    expectedImpact: 'injection',
    expectedBoundary: 'other',
    expectedInjectionFamily: 'cmdi',
    expectedReceiptClass: null,
  },
  {
    name: 'xss-reflected',
    vulnClass: 'xss_reflected',
    cwe: 'CWE-79',
    category: 'xss',
    title: 'Reflected cross-site scripting (executed marker) on /search',
    severity: 'high',
    expectedImpact: 'markup',
    expectedBoundary: 'other',
    expectedInjectionFamily: null,
    expectedReceiptClass: 'xss_stored',
  },
  {
    name: 'bola-cross-tenant',
    vulnClass: 'bola',
    cwe: 'CWE-639',
    category: 'broken-access-control',
    title: 'Cross-tenant object read on /api/orders/:id',
    severity: 'high',
    expectedImpact: 'authorization',
    expectedBoundary: 'access',
    expectedInjectionFamily: null,
    expectedReceiptClass: 'bola',
  },
  {
    name: 'bfla-admin',
    vulnClass: 'bfla',
    cwe: 'CWE-285',
    category: 'broken-access-control',
    title: 'Vertical privilege escalation on /api/admin/users',
    severity: 'high',
    expectedImpact: 'bfla',
    expectedBoundary: 'access',
    expectedInjectionFamily: null,
    expectedReceiptClass: 'bfla',
  },
  {
    name: 'mass-assignment',
    vulnClass: 'mass_assignment',
    cwe: 'CWE-915',
    category: 'mass-assignment',
    title: 'Mass assignment of privileged field "role" on /api/profile',
    severity: 'high',
    expectedImpact: 'mass_assignment',
    expectedBoundary: 'other',
    expectedInjectionFamily: null,
    expectedReceiptClass: 'mass_assignment',
  },
  {
    name: 'csrf-state-change',
    vulnClass: 'csrf',
    cwe: 'CWE-352',
    category: 'csrf',
    title: 'CSRF protection missing on a state-changing request on /api/settings',
    severity: 'high',
    expectedImpact: 'csrf',
    expectedBoundary: 'other',
    expectedInjectionFamily: null,
    expectedReceiptClass: 'csrf',
  },
  {
    name: 'info-disclosure-cred',
    vulnClass: 'info_disclosure',
    cwe: 'CWE-200',
    category: 'sensitive-data-exposure',
    title: 'Credential exposure on an unentitled read on /api/export',
    severity: 'high',
    expectedImpact: 'disclosure',
    expectedBoundary: 'other',
    expectedInjectionFamily: null,
    expectedReceiptClass: 'info_disclosure',
  },
  {
    name: 'info-disclosure-log',
    vulnClass: 'info_disclosure',
    cwe: 'CWE-532',
    category: 'sensitive-data-exposure',
    title: 'Credential reference exposed in an audit/activity read on /api/audit',
    severity: 'high',
    expectedImpact: 'disclosure',
    expectedBoundary: 'other',
    expectedInjectionFamily: null,
    expectedReceiptClass: 'info_disclosure',
  },
  {
    name: 'business-logic-workflow',
    vulnClass: 'business_logic',
    cwe: 'CWE-840',
    category: 'business-logic',
    title: 'Workflow step skip: terminal transition accepted twice on /api/invoices/:id/pay',
    severity: 'medium',
    expectedImpact: 'business_logic',
    expectedBoundary: 'other',
    expectedInjectionFamily: null,
    expectedReceiptClass: 'business_logic',
  },
  {
    name: 'price-tampering',
    vulnClass: 'price_tampering',
    cwe: 'CWE-472',
    category: 'price_tampering',
    title: 'Client-supplied price trusted by the payment step on /api/checkout',
    severity: 'high',
    expectedImpact: 'business_logic',
    expectedBoundary: 'other',
    expectedInjectionFamily: null,
    expectedReceiptClass: 'business_logic',
  },
  {
    name: 'race-double-spend',
    vulnClass: 'race_double_spend',
    cwe: 'CWE-362',
    category: 'race_double_spend',
    title: 'Synchronized burst double-spend on /api/transfers',
    severity: 'critical',
    expectedImpact: 'authorization',
    expectedBoundary: 'other',
    expectedInjectionFamily: null,
    expectedReceiptClass: 'bola',
  },
]

test('R2-15 floor specs: typed-first classifyImpactDescriptor, classifyBoundaryClaim, and per-class baseFields templates', () => {
  const LEGACY_AUTHZ_IMPACT = 'An attacker can read or alter data outside their authorization.'
  const NON_AUTHZ_FLOOR_CLASSES = new Set(['xxe', 'ssrf', 'path_traversal', 'jwt', 'webhook_forgery', 'open_redirect'])

  for (const tc of FLOOR_SPEC_CASES) {
    const built = baseFields('https://app.example.test', tc.title, tc.cwe, tc.category, tc.severity, '{ controlPassed: true, confirmed: true }')

    // Title must never be templated over (preserves endpoint information).
    assert.equal(built.title, tc.title.slice(0, 200), `${tc.name}: baseFields must preserve title verbatim`)

    // Legacy authorization boilerplate must never appear on non-authorization specs.
    assert.notEqual(built.impact, LEGACY_AUTHZ_IMPACT, `${tc.name}: baseFields must not use legacy authorization boilerplate`)

    // Typed-first classification from the built floor spec fields must match the expected table class.
    const actualImpact = classifyImpactDescriptor({
      cwe: built.cwe,
      category: built.category,
      title: built.title,
      impact: built.impact,
    })
    assert.equal(actualImpact, tc.expectedImpact, `${tc.name}: classifyImpactDescriptor(baseFields) mismatch`)

    const actualBoundary = classifyBoundaryClaim({
      cwe: built.cwe,
      category: built.category,
      title: built.title,
      impact: built.impact,
    })
    assert.equal(actualBoundary, tc.expectedBoundary, `${tc.name}: classifyBoundaryClaim(baseFields) mismatch`)

    // Even if poisoned with the old authorization boilerplate + adversarial title/description,
    // typed CWE/vulnClass MUST prevent relabelling XXE, SSRF, traversal, JWT, webhook, or redirect
    // into 'authorization' or 'disclosure'.
    const poisonedImpact = classifyImpactDescriptor({
      cwe: tc.cwe,
      vulnClass: tc.vulnClass,
      category: tc.category,
      title: 'Cross-tenant broken access control authorization bypass',
      impact: LEGACY_AUTHZ_IMPACT,
      description: 'Another user data exposure outside their authorization',
    })
    assert.equal(poisonedImpact, tc.expectedImpact, `${tc.name}: poisoned prose must not override typed impact class`)
    if (NON_AUTHZ_FLOOR_CLASSES.has(tc.vulnClass)) {
      assert.notEqual(actualImpact, 'authorization', `${tc.name}: must NEVER classify as authorization`)
      assert.notEqual(poisonedImpact, 'authorization', `${tc.name}: poisoned prose must NEVER classify as authorization`)
    }

    const poisonedBoundary = classifyBoundaryClaim({
      cwe: tc.cwe,
      vulnClass: tc.vulnClass,
      category: tc.category,
      title: '2FA bypass and cross-tenant IDOR authorization',
      impact: LEGACY_AUTHZ_IMPACT,
    })
    assert.equal(poisonedBoundary, tc.expectedBoundary, `${tc.name}: poisoned prose must not override typed boundary class`)

    // Typed injection family must match expected table value.
    assert.equal(
      injectionFamilyFromTyped({ cwe: tc.cwe, vulnClass: tc.vulnClass, category: tc.category }),
      tc.expectedInjectionFamily,
      `${tc.name}: injectionFamilyFromTyped mismatch`,
    )

    // Floor category must always project to a canonical OWASP coverage category.
    assert.ok(
      categoryToOwaspCoverageCategory(tc.category),
      `${tc.name}: category ${tc.category} must map to an OWASP coverage category`,
    )

    // Receipt class parity on http_chain specs.
    if (tc.expectedReceiptClass !== undefined) {
      const dummySpec = {
        ...built,
        kind: 'http_chain' as const,
        steps: [],
      } as unknown as DeclarativeReplaySpec
      assert.equal(
        receiptVulnClassFor(dummySpec),
        tc.expectedReceiptClass,
        `${tc.name}: receiptVulnClassFor mismatch`,
      )
    }
  }
})

test('R2-15 typed-first inferInjectionFamily: typed override wins over prose, conflicting untyped prose fails closed (never widens to null)', () => {
  const sqliErrorStep: ImpactStep = {
    id: 'p1',
    arm: 'probe',
    method: 'GET',
    route: '/api/diag',
    pathAndQuery: '/api/diag?host=test',
    status: 500,
    actor: { handle: 'member', role: 'member', tenant: 'acme', auth: 'cookie', sameSite: null },
    body: 'SQLITE_ERROR: near "test": syntax error',
  }

  // 1. Explicit context.injectionFamily wins over conflicting prose (fails closed to cmdi).
  const explicitOverride = inferInjectionFamily({
    injectionFamily: 'cmdi',
    title: 'SQL injection in diagnostics search',
    description: 'SQL syntax error triggered by query parameter',
  }, [])
  assert.equal(explicitOverride, 'cmdi')
  assert.equal(
    matchStrippedInjectionFingerprint(sqliErrorStep, explicitOverride),
    null,
    'cmdi family must reject unrelated SQLite error fingerprint',
  )

  // 2. Typed CWE wins over conflicting prose (CWE-78 cmdi vs SQLi prose).
  const typedCweWins = inferInjectionFamily({
    cwe: 'CWE-78',
    title: 'SQL injection in diagnostics endpoint',
    description: 'Database SQL error observed',
  }, [])
  assert.equal(typedCweWins, 'cmdi')
  assert.equal(matchStrippedInjectionFingerprint(sqliErrorStep, typedCweWins), null)

  // 3. Typed non-injection CWE (CWE-639 BOLA) is never hijacked into an injection family by prose.
  assert.equal(
    inferInjectionFamily({
      cwe: 'CWE-639',
      title: 'BOLA reading SQL query audit trail',
      description: 'Cross-tenant read of path traversal log',
    }, []),
    null,
  )

  // 4. Prose-only fallback works when typed descriptors are absent and unambiguous.
  const proseFallback = inferInjectionFamily({
    title: 'SQL injection in search filter',
  }, [])
  assert.equal(proseFallback, 'sqli')
  assert.equal(matchStrippedInjectionFingerprint(sqliErrorStep, proseFallback)?.family, 'sqli')

  // 5. Conflicting untyped prose fails closed to 'ambiguous' (NEVER widens to null any-family search!).
  const ambiguousProse = inferInjectionFamily({
    title: 'SQL injection or command injection in diagnostics parameter',
  }, [])
  assert.equal(ambiguousProse, 'ambiguous')
  assert.equal(
    matchStrippedInjectionFingerprint(sqliErrorStep, ambiguousProse),
    null,
    'ambiguous injection family must fail closed and match zero fingerprints',
  )
})

test('R2-15 severity derivation + IMMUTABLE_CONFIRMED_FINDING_FIELDS includes severity', () => {
  assert.ok(
    (IMMUTABLE_CONFIRMED_FINDING_FIELDS as readonly string[]).includes('severity'),
    'IMMUTABLE_CONFIRMED_FINDING_FIELDS must include severity',
  )

  // open_redirect derives 'medium' deterministically regardless of spec/model severity literal.
  assert.equal(deriveSeverityBandForClass({ receiptVulnClass: 'open_redirect', fallback: 'low' }), 'medium')
  assert.equal(deriveSeverityBandForClass({ cwe: 'CWE-601', fallback: 'low' }), 'medium')
  assert.equal(deriveSeverityBandForClass({ cwe: 'CWE-601', fallback: 'critical' }), 'medium')
  assert.equal(deriveSeverityBandForClass({ receiptVulnClass: 'race_double_spend', fallback: 'low' }), 'critical')
  assert.equal(deriveSeverityBandForClass({ cwe: 'CWE-78', fallback: 'medium' }), 'critical')
  assert.equal(deriveSeverityBandForClass({ receiptVulnClass: 'xxe', fallback: 'low' }), 'high')
  assert.equal(deriveSeverityBandForClass({ receiptVulnClass: 'ssrf', fallback: 'low' }), 'high')

  const openRedirectFinding: Finding = {
    id: 'f-open-redirect-1',
    origin: 'https://app.example.test',
    title: 'Open redirect on /login',
    status: 'pending',
    severity: 'low',
    reason: 'Off-origin redirect confirmed.',
    remediation: 'Allowlist redirect origins.',
    evidenceIds: [],
    scopeRevision: 1,
    category: 'ssrf-redirects',
    cwe: 'CWE-601',
    confidence: 'high',
    verification: 'pending',
    findingKind: 'multi_step_chain',
  }
  const openRedirectSpec = {
    ...baseFields(
      'https://app.example.test',
      'Unvalidated redirect target (off-origin navigation)',
      'CWE-601',
      'open-redirect',
      'low',
      '{ controlPassed: true, confirmed: true }',
    ),
    kind: 'http_chain' as const,
    steps: [
      {
        id: 'p1',
        role: 'probe' as const,
        description: 'probe redirect',
        request: { origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/login?next=https://evil.example' },
      },
    ],
  } as unknown as DeclarativeReplaySpec

  const bound = bindConfirmedFindingIdentity(
    openRedirectFinding,
    openRedirectSpec,
    {
      verdict: 'confirmed',
      outcome: { controlPassed: true, confirmed: true, observed: '302', expected: '200', reason: 'confirmed' },
      exchanges: [],
      exchangeIds: [],
      evidencePayload: {},
      evidenceSha256: '0'.repeat(64),
      receipt: {
        mode: 'strict',
        receipt: {
          vulnClass: 'open_redirect',
          target: { origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/login?next=https://evil.example' },
          exchangeIds: ['ex-1'],
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: 'off-origin redirect',
        },
        verification: {
          confirmed: true,
          vulnClass: 'open_redirect',
          rule: 'open_redirect',
          reason: 'off-origin redirect verified',
          observed: '302',
          expected: 'same-origin',
        },
      },
    } as unknown as Parameters<typeof bindConfirmedFindingIdentity>[2],
  )
  assert.equal(bound.severity, 'medium', 'bindConfirmedFindingIdentity must derive medium severity for open_redirect')
  assert.equal(bound.cwe, 'CWE-601')
  assert.equal(SEVERITY_BY_CLASS.open_redirect, 'medium')
})

test('R3-11: live mislabels eliminated (cross_tenant_read/write, injection CWE-89/943, xss/xxe/csrf/webhook_forgery OWASP parity)', () => {
  // 1. cross_tenant_read & cross_tenant_write map to broken-access-control / CWE-639 (NEVER CWE-200).
  for (const cls of ['cross_tenant_read', 'cross_tenant_write']) {
    const fam = cweFamilyForReceiptClass(cls)
    assert.equal(fam.cwe, 'CWE-639', `${cls} must map to CWE-639`)
    assert.ok(fam.family.includes('CWE-639') && fam.family.includes('CWE-284'), `${cls} family must include CWE-639 and CWE-284`)
    assert.equal(fam.category, 'broken-access-control', `${cls} must map to broken-access-control`)
    assert.equal(fam.unclassified, false)
    assert.equal(agentProofAttribution(cls).cwe, 'CWE-639')
    assert.equal(agentProofAttribution(cls).category, 'broken-access-control')
    assert.equal(categoryToOwaspCoverageCategory(cls), fam.category)
  }

  // 2. url_redirect, price_tampering, workflow_bypass map cleanly (never CWE-200).
  assert.equal(cweFamilyForReceiptClass('url_redirect').cwe, 'CWE-601')
  assert.equal(cweFamilyForReceiptClass('url_redirect').category, 'ssrf-redirects')
  assert.equal(cweFamilyForReceiptClass('price_tampering').cwe, 'CWE-472')
  assert.equal(cweFamilyForReceiptClass('price_tampering').category, 'business-logic-race')
  assert.equal(cweFamilyForReceiptClass('workflow_bypass').cwe, 'CWE-840')
  assert.equal(cweFamilyForReceiptClass('workflow_bypass').category, 'business-logic-race')

  // 3. Injection drift-gate invariant (F1): specific receipts accept their CWE + generic CWE-74
  //    one-directionally, while generic `injection` stays tight (['CWE-74']) so re-verifying a
  //    confirmed CWE-89/CWE-78/CWE-1336/CWE-943 finding under generic `injection` reports drift.
  const sqliFam = cweFamilyForReceiptClass('sqli')
  assert.ok(sqliFam.family.includes('CWE-89') && sqliFam.family.includes('CWE-564') && sqliFam.family.includes('CWE-74'))
  const nosqliFam = cweFamilyForReceiptClass('nosqli')
  assert.ok(nosqliFam.family.includes('CWE-943') && nosqliFam.family.includes('CWE-74'))
  assert.equal(nosqliFam.family.includes('CWE-89'), false, 'nosqli family must not accept SQLi CWE-89')
  const inj = cweFamilyForReceiptClass('injection')
  assert.deepEqual(inj.family, ['CWE-74'], 'generic injection family must stay tight (CWE-74 only)')
  assert.equal(inj.category, 'injection-input')
  assert.equal(isCweConsistentWithReceiptClass('CWE-89', 'injection'), false, 'CWE-89 under generic injection receipt must report drift')
  assert.equal(isCweConsistentWithReceiptClass('CWE-78', 'injection'), false, 'CWE-78 under generic injection receipt must report drift')
  assert.equal(isCweConsistentWithReceiptClass('CWE-1336', 'injection'), false, 'CWE-1336 under generic injection receipt must report drift')
  assert.equal(isCweConsistentWithReceiptClass('CWE-943', 'injection'), false, 'CWE-943 under generic injection receipt must report drift')
  assert.equal(isCweConsistentWithReceiptClass('CWE-74', 'injection'), true)
  assert.equal(isCweConsistentWithReceiptClass('CWE-74', 'sqli'), true, 'specific sqli receipt may confirm generic CWE-74 one-directionally')
  assert.equal(isCweConsistentWithReceiptClass('CWE-89', 'sqli'), true)
  assert.equal(isCweConsistentWithReceiptClass('CWE-943', 'nosqli'), true)

  // 4. XSS, XXE, CSRF, and webhook_forgery OWASP cells match across exec-verify and coverage-category.
  for (const [cls, expectedOwasp, expectedCwe] of [
    ['xss', 'cors-client-side', 'CWE-79'],
    ['xss_reflected', 'cors-client-side', 'CWE-79'],
    ['xss_stored', 'cors-client-side', 'CWE-79'],
    ['dom_xss', 'cors-client-side', 'CWE-79'],
    ['xxe', 'injection-input', 'CWE-611'],
    ['blind_xxe', 'injection-input', 'CWE-611'],
    ['csrf', 'cors-client-side', 'CWE-352'],
    ['webhook_forgery', 'auth-identity', 'CWE-345'],
  ] as const) {
    assert.equal(cweFamilyForReceiptClass(cls).category, expectedOwasp, `exec-verify ${cls} OWASP mismatch`)
    assert.equal(cweFamilyForReceiptClass(cls).cwe, expectedCwe, `exec-verify ${cls} CWE mismatch`)
    assert.equal(agentProofAttribution(cls).category, expectedOwasp, `attribution ${cls} OWASP mismatch`)
    assert.equal(categoryToOwaspCoverageCategory(cls), expectedOwasp, `coverage-category ${cls} OWASP mismatch`)
  }
})

test('R3-11: every known receipt class resolves without CWE-200 fallthrough and unknown classes stay visible as unclassified', () => {
  const GENUINE_DISCLOSURE_CLASSES = new Set([
    'disclosure',
    'info_disclosure',
    'information_disclosure',
    'sensitive_data_exposure',
    'secret_disclosure',
    'secret_disclosed',
    'secret_leak',
    'data_exposure',
    'pii_exposure',
  ])

  const ALL_RECEIPT_CLASSES = [
    ...new Set([
      ...Object.values(CWE_TO_RECEIPT_CLASS),
      ...Object.keys(SEVERITY_BY_CLASS),
      ...REGISTERED_V8_ORACLE_FAMILIES,
      // Single-hop receiptRuleFor classes from src/server/proof-receipt.ts
      'ssrf', 'xxe', 'blind_ssrf', 'blind_xxe', 'oob', 'webhook_forgery',
      'blind_sqli', 'sqli_time', 'sql_time', 'timing',
      'sqli', 'sql_boolean', 'sql_boolean_diff', 'boolean_sqli', 'boolean_differential',
      'sqli_status', 'sql_status', 'sql_status_diff', 'status_sqli', 'status_boolean',
      'open_redirect', 'redirect', 'url_redirect', 'unvalidated_redirect',
      'race', 'race_double_spend', 'race_condition', 'race_burst', 'double_spend',
      'oversell', 'inventory_oversell', 'conserved_balance', 'toctou',
      'auth_bypass', 'jwt_forgery', 'broken_auth', 'auth_protocol', 'token_forgery', 'authentication_bypass',
      'signed_url_mint', 'presigned_url_mint', 'signed_url_traversal', 'storage_signed_url',
      'gcs_signed_url', 's3_presigned_url', 'azure_sas_mint',
      'bola', 'idor', 'authorization', 'broken-access-control', 'access_control',
      'cross_tenant', 'cross_tenant_read', 'cross_tenant_write',
      'bfla', 'privilege_escalation', 'mass_assignment', 'csrf',
      'business_logic', 'invariant_violation', 'workflow_skip', 'workflow_bypass', 'price_tampering',
      'xss', 'xss_stored', 'xss_reflected', 'dom_xss', 'markup', 'html_injection',
      'disclosure', 'info_disclosure', 'secret_disclosed', 'secret_disclosure',
      'injection', 'injection-input', 'injection_input', 'sqli_error',
      'nosqli', 'nosql_injection', 'ssti', 'template_injection',
      'command_injection', 'cmdi', 'path_traversal', 'directory_traversal', 'lfi',
      'browser_xss', 'browser_dom', 'postmessage',
    ]),
  ].sort()

  for (const cls of ALL_RECEIPT_CLASSES) {
    const fam = cweFamilyForReceiptClass(cls)
    const attr = agentProofAttribution(cls)
    assert.equal(fam.unclassified, false, `known receipt class "${cls}" must not be unclassified`)
    assert.equal(attr.unclassified, false, `known attribution class "${cls}" must not be unclassified`)
    assert.equal(fam.cwe, attr.cwe, `cweFamilyForReceiptClass and agentProofAttribution must agree on CWE for "${cls}"`)
    assert.equal(fam.category, attr.category, `cweFamilyForReceiptClass and agentProofAttribution must agree on category for "${cls}"`)
    assert.equal(
      categoryToOwaspCoverageCategory(cls),
      fam.category,
      `coverage-category and exec-verify must agree on OWASP cell for "${cls}"`,
    )
    if (!GENUINE_DISCLOSURE_CLASSES.has(cls)) {
      assert.notEqual(fam.cwe, 'CWE-200', `non-disclosure receipt class "${cls}" must NEVER fall through to CWE-200`)
      assert.notEqual(attr.cwe, 'CWE-200', `non-disclosure attribution "${cls}" must NEVER fall through to CWE-200`)
    }
  }

  // Unknown receipt class maps explicitly to 'unclassified' (NEVER CWE-200 / misconfig-exposure).
  const unknownFam = cweFamilyForReceiptClass('novel_unmapped_receipt_class')
  assert.equal(unknownFam.cwe, UNCLASSIFIED_TAXONOMY_KEY)
  assert.equal(unknownFam.category, UNCLASSIFIED_TAXONOMY_KEY)
  assert.deepEqual(unknownFam.family, [])
  assert.equal(unknownFam.unclassified, true)

  const unknownAttr = agentProofAttribution('novel_unmapped_receipt_class')
  assert.equal(unknownAttr.cwe, UNCLASSIFIED_TAXONOMY_KEY)
  assert.equal(unknownAttr.category, UNCLASSIFIED_TAXONOMY_KEY)
  assert.equal(unknownAttr.unclassified, true)
  assert.equal(lookupVulnTaxonomy('novel_unmapped_receipt_class'), null)

  // bindConfirmedFindingIdentity keeps unclassified findings visible (never drops or defaults to CWE-200).
  const unknownFinding: Finding = {
    id: 'f-unknown-class-1',
    origin: 'https://app.example.test',
    title: 'Novel boundary finding',
    status: 'pending',
    severity: 'high',
    reason: 'Confirmed by receipt.',
    remediation: 'Review transcript.',
    evidenceIds: [],
    scopeRevision: 1,
    category: 'misconfig-exposure',
    cwe: 'CWE-200',
  }
  const unknownSpec = {
    ...baseFields(
      'https://app.example.test',
      'Novel boundary finding',
      'CWE-200',
      'misconfig-exposure',
      'high',
      '{ controlPassed: true, confirmed: true }',
    ),
    kind: 'http_chain' as const,
    steps: [
      {
        id: 'p1',
        role: 'probe' as const,
        description: 'probe',
        request: { origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/api/novel' },
      },
    ],
  } as unknown as DeclarativeReplaySpec
  const boundUnknown = bindConfirmedFindingIdentity(
    unknownFinding,
    unknownSpec,
    {
      verdict: 'confirmed',
      outcome: { controlPassed: true, confirmed: true, observed: 'diff', expected: 'blocked', reason: 'confirmed' },
      exchanges: [],
      exchangeIds: [],
      evidencePayload: {},
      evidenceSha256: '1'.repeat(64),
      receipt: {
        mode: 'strict',
        receipt: {
          vulnClass: 'novel_unmapped_receipt_class',
          target: { origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/api/novel' },
          exchangeIds: ['ex-1'],
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: 'unmapped receipt class',
        },
        verification: {
          confirmed: true,
          vulnClass: 'novel_unmapped_receipt_class',
          rule: 'impact',
          reason: 'verified',
          observed: 'diff',
          expected: 'blocked',
        },
      },
    } as unknown as Parameters<typeof bindConfirmedFindingIdentity>[2],
  )
  assert.equal(boundUnknown.cwe, UNCLASSIFIED_TAXONOMY_KEY)
  assert.equal(boundUnknown.category, UNCLASSIFIED_TAXONOMY_KEY)
  assert.equal(boundUnknown.title, 'Novel boundary finding')
})

test('R3-11: src/vuln-taxonomy.ts is browser-safe, shared by coverage-category, and exec-verify delegates safety primitives', () => {
  assert.ok(VULN_TAXONOMY.length >= 20)
  assert.equal(CANONICAL_CLASS_TO_OWASP['xss'], 'cors-client-side')
  assert.equal(CANONICAL_CLASS_TO_OWASP['xxe'], 'injection-input')
  assert.equal(CANONICAL_CLASS_TO_OWASP['cross-tenant-read'], 'broken-access-control')

  const taxonomyImportLines = readFileSync(join(REPO_ROOT, 'src', 'vuln-taxonomy.ts'), 'utf8')
    .split('\n')
    .filter(line => line.trim().startsWith('import '))
    .join('\n')
  assert.equal(taxonomyImportLines.includes("'node:") || taxonomyImportLines.includes('"node:'), false, 'src/vuln-taxonomy.ts must not import node:* builtins')
  assert.equal(taxonomyImportLines.includes('server/'), false, 'src/vuln-taxonomy.ts must not import src/server/*')

  // Safety-primitive consolidation in exec-verify.ts (R3-11 retires final R3-10 clone debt).
  assert.strictEqual(execVerifyIsSensitiveRepoEntry, safetyIsSensitiveRepoEntry)
  assert.strictEqual(execVerifyIsSensitiveRepoRelativePath, safetyIsSensitiveRepoRelativePath)

  // R3-11 F2 single-source conformance guard: every VULN_TAXONOMY entry's canonicalCwe MUST
  // dedupe-intersect every member of its cweFamily, except explicitly documented exceptions.
  const exceptionSet = new Set(DEDUPE_FAMILY_EXCEPTIONS.map(ex => `${ex.entryId}::${ex.cwe}`))
  for (const entry of VULN_TAXONOMY) {
    for (const memberCwe of entry.cweFamily) {
      const key = `${entry.id}::${memberCwe}`
      if (exceptionSet.has(key)) {
        assert.equal(
          cweFamiliesIntersect(entry.canonicalCwe, memberCwe),
          false,
          `documented dedupe veto exception ${key} should remain disjoint`,
        )
        continue
      }
      assert.equal(
        cweFamiliesIntersect(entry.canonicalCwe, memberCwe),
        true,
        `VULN_TAXONOMY ${entry.id}: canonicalCwe ${entry.canonicalCwe} must dedupe-intersect cweFamily member ${memberCwe}`,
      )
    }
  }

  // R3-11 N2: overly broad non-kernel aliases must not bind to specific CWEs in VULN_TAXONOMY.
  for (const broad of ['cache', 'auth', 'authn', 'authentication', 'session', 'replay_attack', 'rate_limit_bypass', 'webhook']) {
    assert.equal(lookupVulnTaxonomy(broad), null, `overly broad alias "${broad}" must not map in VULN_TAXONOMY`)
    assert.equal(cweFamilyForReceiptClass(broad).unclassified, true, `broad alias "${broad}" must remain unclassified`)
  }
})
