// @kernel
/**
 * R3-13 — Authoritative OracleSpec Registry, Admission Gate, Cross-Module Table Agreement,
 * Strongest-Wins `labelToOracle()`, and Lateral Same-CWE FP Permutation Suite.
 *
 * Pure behavioral/runtime suite (zero `readFileSync(src/**)` + regex assertions).
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import {
  IMPACT_CLASS_CWES,
  classifyBoundaryClaim,
  classifyImpactDescriptor,
  evidenceClassLabel,
  type RoleName,
} from '../src/server/oracle-invariants.ts'
import {
  DEFAULT_ORACLE_SPEC_REGISTRY,
  REGISTERED_SINGLE_HOP_RULES,
  REGISTERED_V8_FAMILIES,
  canonicalCweForOracle,
  createOracleSpecRegistry,
  getRegisteredClaimEvaluatorSpecs,
  isSignedUrlMintLabel,
  labelToOracle,
  listRegisteredClaimEvaluatorKinds,
  registerOracle,
  registerOracleClaimEvaluator,
  resolveBoundaryClassForLabel,
  resolveDescriptorImpactClass,
  validateOracleSpec,
  type OracleClaimKind,
  type OracleSpec,
} from '../src/server/oracle-spec.ts'
import { buildProofReceipt, receiptRuleFor, verifyReceipt } from '../src/server/proof-receipt.ts'
import {
  REGISTERED_V8_ORACLE_FAMILIES,
  SINGLE_HOP_ORACLE_RULES,
  defaultTerminalOracleRegistry,
  evaluateTerminalOracle,
} from '../src/server/terminal-oracle-registry.ts'
import { TERMINAL_CLASS_CONTRACT, resolveTerminalContract } from '../src/server/v8-oracle-hydrate.ts'
import { TranscriptStore, evaluateClaims } from '../src/server/verify-claims.ts'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const CORPUS_DIR = join(REPO_ROOT, 'tests', 'parity', 'corpus')
const TEST_SIGNING_KEY = 'r3-13-oracle-admission-signing-key-2026'

interface CorpusFile {
  id: string
  side: 'tp' | 'fp' | 'retest'
  expected: { confirmed: boolean }
  paths: {
    replay?: boolean
    floorReceipt?: boolean
    evaluateClaims?: boolean
    composite?: boolean
    proofReceipt?: boolean
  }
  canonicalLabel: { cwe?: string; vulnClass?: string }
  personas: Array<{
    handle: string
    role: RoleName
    tenant: string
    auth: 'bearer' | 'cookie' | 'header' | 'unknown'
    headerName: string
    headerValue: string
  }>
  exchanges: Array<{
    id: string
    arm: 'control' | 'probe' | 'setup' | 'cleanup'
    method: string
    pathAndQuery: string
    persona: string | null
    requestJson?: unknown
    requestHeaders?: Record<string, string>
    status: number
    responseHeaders: Record<string, string>
    body: string
    durationMs?: number
    evidenceRole?: string
  }>
  proofReceipt?: {
    vulnClass?: string
    param?: string
    targetMethod?: string
    targetPathAndQuery?: string
    claimedDelta?: string
    oobEvents?: Array<{ id: string }>
  }
  composite?: {
    v8OracleInput?: { family?: string }
  }
}

function loadCorpusFiles(): CorpusFile[] {
  return readdirSync(CORPUS_DIR)
    .filter(f => f.endsWith('.json'))
    .sort()
    .map(f => JSON.parse(readFileSync(join(CORPUS_DIR, f), 'utf8')) as CorpusFile)
}

function makeValidSpec(overrides: Partial<OracleSpec> = {}): OracleSpec {
  return {
    id: 'test:custom_oracle',
    kind: 'single_hop',
    singleHopRule: 'redirect',
    canonicalVulnClass: 'custom_redirect',
    cwes: ['CWE-601'],
    labels: ['custom_redirect'],
    terminalContract: 'injection_or_redirect',
    boundaryClass: 'other',
    descriptorImpactClass: 'other',
    claimKinds: ['impact'],
    strictnessRank: 90,
    inputs: [
      { name: 'host_redirect_header', provenance: 'host_observed', required: true },
      { name: 'exchange_citations', provenance: 'worker_citation', required: true },
    ],
    controls: [
      { kind: 'same_origin_control', description: 'Benign same-origin control verifying no unintended redirect.' },
    ],
    bindingKind: 'canary',
    reflectionPolicy: 'not_applicable',
    publicnessPolicy: 'not_applicable',
    archetypeExemptions: [],
    ...overrides,
  }
}

// ============================================================================
// 1. registerOracle() admission gate & complete spec contract
// ============================================================================

test('R3-13 admission gate: every built-in OracleSpec passes validation with complete provenance, controls, and binding', () => {
  const specs = DEFAULT_ORACLE_SPEC_REGISTRY.list()
  assert.ok(specs.length >= 24, `expected >= 24 registered OracleSpecs (single-hop + v8), got ${specs.length}`)

  for (const spec of specs) {
    const errors = validateOracleSpec(spec)
    assert.deepEqual(errors, [], `Built-in OracleSpec "${spec.id}" failed admission validation: ${JSON.stringify(errors)}`)
    assert.ok(spec.inputs.some(i => i.provenance === 'host_observed' || i.provenance === 'host_minted'), `Spec "${spec.id}" must require host-observed or host-minted input`)
    assert.ok(spec.controls.length >= 1, `Spec "${spec.id}" must declare at least 1 legitimate negative control`)
    assert.ok(spec.cwes.length >= 1, `Spec "${spec.id}" must declare at least 1 canonical CWE`)
    assert.ok(Object.isFrozen(spec), `Spec "${spec.id}" must be frozen`)
  }
})

test('R3-13 admission gate: registerOracle() rejects incomplete, duplicate, unbound, or post-seal registrations', () => {
  const reg = createOracleSpecRegistry()

  // Valid custom spec registers cleanly.
  const registered = registerOracle(makeValidSpec(), reg)
  assert.equal(registered.id, 'test:custom_oracle')
  assert.equal(reg.get('test:custom_oracle')?.canonicalVulnClass, 'custom_redirect')

  // Duplicate ID rejected.
  assert.throws(() => registerOracle(makeValidSpec(), reg), /already registered/i)

  // Missing negative controls rejected.
  assert.throws(
    () => registerOracle(makeValidSpec({ id: 'test:no_controls', controls: [] }), reg),
    /negative control/i,
  )

  // Worker-citation-only inputs (no host-observed/host-minted provenance) rejected.
  assert.throws(
    () =>
      registerOracle(
        makeValidSpec({
          id: 'test:worker_only_inputs',
          inputs: [{ name: 'worker_claim', provenance: 'worker_citation', required: true }],
        }),
        reg,
      ),
    /host_observed or host_minted/i,
  )

  // none_ticketed binding without ticket rejected.
  assert.throws(
    () =>
      registerOracle(
        makeValidSpec({
          id: 'test:unbound_no_ticket',
          bindingKind: 'none_ticketed',
          bindingTicket: undefined,
        }),
        reg,
      ),
    /bindingTicket/i,
  )

  // Invalid CWE rejected.
  assert.throws(
    () => registerOracle(makeValidSpec({ id: 'test:bad_cwe', cwes: ['CWE-0'] }), reg),
    /invalid CWE/i,
  )

  // Impact rule missing impactClass rejected.
  assert.throws(
    () =>
      registerOracle(
        makeValidSpec({ id: 'test:impact_no_class', singleHopRule: 'impact', impactClass: undefined }),
        reg,
      ),
    /requires a valid impactClass/i,
  )

  // Empty/whitespace labelPrefixes rejected (Advisory B).
  assert.throws(
    () => registerOracle(makeValidSpec({ id: 'test:empty_prefix', labels: ['pref_a'], labelPrefixes: [''] }), reg),
    /labelPrefix/i,
  )

  // Bare CWE token as a label rejected (Blocking 1 / Advisory B).
  assert.throws(
    () => registerOracle(makeValidSpec({ id: 'test:cwe_label', labels: ['cwe-89'] }), reg),
    /non-CWE/i,
  )

  // v8_family with non-v8_* terminalContract rejected (Advisory B).
  assert.throws(
    () =>
      registerOracle(
        makeValidSpec({
          id: 'test:v8_bad_contract',
          kind: 'v8_family',
          singleHopRule: undefined,
          v8Family: 'dual_tenant_abac',
          labels: ['v8_bad_contract'],
          terminalContract: 'access_control',
        }),
        reg,
      ),
    /v8_\* terminalContract/i,
  )

  // Shared label with disagreeing terminalContract rejected (Advisory A).
  assert.throws(
    () =>
      registerOracle(
        makeValidSpec({
          id: 'test:shared_label_conflict',
          labels: ['custom_redirect'],
          terminalContract: 'oob',
        }),
        reg,
      ),
    /disagrees on terminalContract/i,
  )

  // Expired archetype exemption rejected (Advisory B).
  assert.throws(
    () =>
      registerOracle(
        makeValidSpec({
          id: 'test:expired_exemption',
          labels: ['expired_ex_label'],
          archetypeExemptions: [{ archetype: 'public_endpoint', ticket: 'R3-99', reason: 'expired', expires: '2020-01-01' }],
        }),
        reg,
      ),
    /expired/i,
  )

  // Post-seal registration into DEFAULT_ORACLE_SPEC_REGISTRY or a sealed registry rejected.
  reg.seal()
  assert.throws(() => registerOracle(makeValidSpec({ id: 'test:post_seal' }), reg), /sealed/i)
  assert.throws(() => registerOracle(makeValidSpec({ id: 'test:post_seal_default' })), /sealed/i)
})

// ============================================================================
// 2. Cross-module table agreement (0 drift across all 5 kernel modules)
// ============================================================================

test('R3-13 agreement gate: terminal-oracle-registry, proof-receipt, v8-oracle-hydrate, oracle-invariants, and verify-claims agree with OracleSpec (0 drift)', () => {
  // 2a. Rule & V8 family arrays match identically across registry and runtime dispatch.
  assert.deepEqual([...SINGLE_HOP_ORACLE_RULES], [...REGISTERED_SINGLE_HOP_RULES])
  assert.deepEqual([...REGISTERED_V8_ORACLE_FAMILIES], [...REGISTERED_V8_FAMILIES])
  assert.deepEqual(new Set(defaultTerminalOracleRegistry.listRegisteredRules()), new Set(REGISTERED_SINGLE_HOP_RULES))
  assert.deepEqual(new Set(defaultTerminalOracleRegistry.listRegisteredV8Families()), new Set(REGISTERED_V8_FAMILIES))
  assert.equal(defaultTerminalOracleRegistry.listOracleSpecs().length, DEFAULT_ORACLE_SPEC_REGISTRY.list().length)

  // 2b. Every registered OracleSpec label agrees across receiptRuleFor, resolveTerminalContract,
  //     TERMINAL_CLASS_CONTRACT, classifyBoundaryClaim, and classifyImpactDescriptor.
  const drifts: string[] = []
  for (const spec of DEFAULT_ORACLE_SPEC_REGISTRY.list()) {
    for (const label of spec.labels) {
      const terminal = resolveTerminalContract(label)
      if (terminal !== spec.terminalContract) {
        drifts.push(`terminalContract(${label}): got ${String(terminal)}, expected ${spec.terminalContract}`)
      }
      if (TERMINAL_CLASS_CONTRACT[label] !== spec.terminalContract) {
        drifts.push(`TERMINAL_CLASS_CONTRACT[${label}]: got ${String(TERMINAL_CLASS_CONTRACT[label])}, expected ${spec.terminalContract}`)
      }
      if (spec.kind === 'single_hop') {
        if (label === 'webhook_forgery') {
          const withOob = receiptRuleFor(label, { oobEventIds: ['oob-1'] })
          const withoutOob = receiptRuleFor(label, { oobEventIds: [] })
          if (withOob.rule !== 'oob') drifts.push(`receiptRuleFor(webhook_forgery, [oob]): got ${withOob.rule}`)
          if (withoutOob.rule !== 'webhook') drifts.push(`receiptRuleFor(webhook_forgery, []): got ${withoutOob.rule}`)
        } else {
          const got = receiptRuleFor(label)
          if (got.rule !== spec.singleHopRule) {
            drifts.push(`receiptRuleFor(${label}).rule: got ${got.rule}, expected ${String(spec.singleHopRule)}`)
          }
          if (spec.singleHopRule === 'impact' && got.impactClass !== spec.impactClass) {
            drifts.push(`receiptRuleFor(${label}).impactClass: got ${String(got.impactClass)}, expected ${String(spec.impactClass)}`)
          }
        }
      }
      const boundary = classifyBoundaryClaim({ vulnClass: label })
      if (boundary !== spec.boundaryClass) {
        drifts.push(`classifyBoundaryClaim(${label}): got ${boundary}, expected ${spec.boundaryClass}`)
      }
      const expectedDescImpact = resolveDescriptorImpactClass(label) ?? 'other'
      const actualDescImpact = classifyImpactDescriptor({ vulnClass: label })
      if (expectedDescImpact !== actualDescImpact) {
        drifts.push(`classifyImpactDescriptor(${label}): got ${actualDescImpact}, expected ${String(expectedDescImpact)}`)
      }
    }

    // Evidence alignment tables agree with OracleSpec.
    if (spec.evidenceAlignment) {
      const evLabel = evidenceClassLabel(spec.evidenceAlignment.key)
      assert.deepEqual(evLabel, {
        vulnClass: spec.evidenceAlignment.vulnClass,
        cwe: spec.evidenceAlignment.cwe,
        category: spec.evidenceAlignment.category,
      })
      assert.deepEqual(IMPACT_CLASS_CWES[spec.evidenceAlignment.key], [...spec.evidenceAlignment.cweNumbers])
    }
  }

  // Previously-drifting labels specifically called out in R3-13 must now be mapped cleanly.
  assert.equal(resolveTerminalContract('timing'), 'injection_or_redirect')
  assert.equal(resolveTerminalContract('signed_url_mint'), 'access_control')
  assert.deepEqual(drifts, [], `Cross-module oracle table drift detected:\n  - ${drifts.join('\n  - ')}`)

  // 2c. Every claimKind declared in ANY registered OracleSpec has exactly one registered evaluator
  //     whose bound spec list includes every declaring spec, and the evaluator registry is sealed.
  const declaredClaimKinds = new Set<OracleClaimKind>()
  for (const spec of DEFAULT_ORACLE_SPEC_REGISTRY.list()) {
    for (const ck of spec.claimKinds) declaredClaimKinds.add(ck)
  }
  const registeredKinds = listRegisteredClaimEvaluatorKinds()
  assert.equal(new Set(registeredKinds).size, registeredKinds.length, 'claim evaluator kinds must be unique')
  for (const kind of declaredClaimKinds) {
    assert.ok(registeredKinds.includes(kind), `verify-claims.ts missing registered OracleSpec claim evaluator for "${kind}"`)
    const declaringIds = DEFAULT_ORACLE_SPEC_REGISTRY.list().filter(s => s.claimKinds.includes(kind)).map(s => s.id)
    const boundIds = getRegisteredClaimEvaluatorSpecs(kind)
    assert.deepEqual([...boundIds].sort(), [...declaringIds].sort(), `claim evaluator "${kind}" must bind every declaring OracleSpec`)
    assert.deepEqual([...defaultTerminalOracleRegistry.claimEvaluatorSpecsFor(kind)], [...boundIds])
  }
  // Post-seal overwrite / registration must fail closed (Blocking 2).
  assert.throws(
    () => registerOracleClaimEvaluator('oob', 'oob', () => ({ passed: true })),
    /sealed/i,
  )
})

// ============================================================================
// 3. Strongest / canonical labelToOracle() — NEVER weakest & ZERO CWE hijacking!
// ============================================================================

test('R3-13 labelToOracle(): exact-label-only rejects bare CWE tokens, cross-family CWE mismatches fail closed, and same-CWE queries pick the STRONGEST spec', () => {
  // Blocking 1: bare CWE tokens MUST return null/false/'none' on EVERY label-only resolver.
  for (const bareCwe of ['CWE-79', 'CWE-639', 'CWE-89', 'cwe-89', 'CWE-287']) {
    assert.equal(resolveTerminalContract(bareCwe), null, `resolveTerminalContract(${bareCwe}) must be null`)
    assert.equal(receiptRuleFor(bareCwe).rule, 'none', `receiptRuleFor(${bareCwe}) must be 'none'`)
    assert.equal(isSignedUrlMintLabel(bareCwe), false, `isSignedUrlMintLabel(${bareCwe}) must be false`)
    assert.equal(resolveDescriptorImpactClass(bareCwe), null, `resolveDescriptorImpactClass(${bareCwe}) must be null`)
    assert.equal(resolveBoundaryClassForLabel(bareCwe), null, `resolveBoundaryClassForLabel(${bareCwe}) must be null`)
    assert.equal(labelToOracle({ label: bareCwe, exactLabelOnly: true }), null, `exactLabelOnly must reject ${bareCwe}`)
  }

  // Blocking 1(c): cross-family label + CWE mismatch MUST fail closed (never hijack to another CWE family).
  assert.equal(labelToOracle({ vulnClass: 'sqli_status', cwe: 'CWE-79', scope: 'single_hop' }), null)
  assert.equal(labelToOracle({ label: 'sqli_status', cwe: 'CWE-79' }), null)
  assert.equal(canonicalCweForOracle({ label: 'sqli_status', cwe: 'CWE-79' }), null)
  assert.equal(defaultTerminalOracleRegistry.canonicalCweFor({ label: 'sqli_status', cwe: 'CWE-79' }), null)

  // CWE-89 candidates: boolean (95) > timing (80) > impact:injection (75) > status_differential (60).
  const cwe89 = labelToOracle({ cwe: 'CWE-89', scope: 'single_hop' })
  assert.equal(cwe89?.id, 'boolean')
  assert.equal(cwe89?.strictnessRank, 95)
  assert.equal(canonicalCweForOracle({ cwe: 'CWE-89', scope: 'single_hop' }), 'CWE-89')

  // Attaching a weaker label (`sqli_status`, rank 60) alongside CWE-89 MUST NOT downgrade away from `boolean` (rank 95).
  assert.equal(labelToOracle({ vulnClass: 'sqli_status', cwe: 'CWE-89', scope: 'single_hop' })?.id, 'boolean')
  assert.equal(labelToOracle({ label: 'sqli_status', canonical: true, scope: 'single_hop' })?.id, 'boolean')
  assert.equal(labelToOracle({ labels: ['sqli_status', 'sqli_error'], scope: 'single_hop' })?.id, 'impact:injection')
  assert.equal(labelToOracle({ labels: ['sqli_status', 'sqli_time', 'sqli'], scope: 'single_hop' })?.id, 'boolean')
  assert.equal(labelToOracle('CWE-89')?.id, 'boolean')

  // CWE-79: browser (95) beats impact:markup (85).
  assert.equal(labelToOracle({ cwe: 'CWE-79', scope: 'single_hop' })?.id, 'browser')
  assert.equal(labelToOracle({ vulnClass: 'xss_reflected', cwe: 'CWE-79', scope: 'single_hop' })?.id, 'browser')

  // Blocking 1(d): CWE-639 general BOLA stays on `impact:authorization` (single-hop) and is NEVER hijacked by `impact:signed_url_mint` subtype!
  assert.equal(labelToOracle({ cwe: 'CWE-639', scope: 'all' })?.id, 'v8:dual_tenant_abac')
  assert.equal(labelToOracle({ cwe: 'CWE-639', scope: 'single_hop' })?.id, 'impact:authorization')
  assert.equal(labelToOracle({ vulnClass: 'bola', cwe: 'CWE-639', scope: 'single_hop' })?.id, 'impact:authorization')
  assert.equal(labelToOracle({ label: 'bola', canonical: true, scope: 'single_hop' })?.id, 'impact:authorization')
  assert.equal(labelToOracle({ vulnClass: 'signed_url_mint', scope: 'single_hop' })?.id, 'impact:signed_url_mint')

  // CWE-840: v8:economic_conservation (98) > conserved_balance (92) > impact:business_logic (80).
  assert.equal(labelToOracle({ cwe: 'CWE-840', scope: 'all' })?.id, 'v8:economic_conservation')
  assert.equal(labelToOracle({ cwe: 'CWE-840', scope: 'single_hop' })?.id, 'conserved_balance')

  // webhook_forgery defaults to stronger oob (95) unless oobEventIds is explicitly empty [].
  assert.equal(labelToOracle({ vulnClass: 'webhook_forgery', scope: 'single_hop' })?.id, 'oob')
  assert.equal(labelToOracle({ vulnClass: 'webhook_forgery', oobEventIds: [], scope: 'single_hop' })?.id, 'webhook')
  assert.equal(labelToOracle({ vulnClass: 'webhook_forgery', oobEventIds: ['oob-1'], scope: 'single_hop' })?.id, 'oob')

  // Reported CWE always comes from spec.cwes[0].
  for (const spec of DEFAULT_ORACLE_SPEC_REGISTRY.list()) {
    assert.equal(canonicalCweForOracle({ label: spec.canonicalVulnClass, scope: spec.kind }), labelToOracle({ label: spec.canonicalVulnClass, scope: spec.kind })?.cwes[0] ?? null)
  }
})

// ============================================================================
// 4. Corpus coverage + Lateral same-CWE permutation over EVERY FP corpus case
// ============================================================================

test('R3-13 corpus & lateral same-CWE permutation: every single-hop rule has corpus coverage and zero FP cases flip under same-CWE sibling relabeling', () => {
  const corpus = loadCorpusFiles()
  assert.ok(corpus.length >= 16, `expected >= 16 parity corpus cases, got ${corpus.length}`)

  // Every single-hop rule in REGISTERED_SINGLE_HOP_RULES must have >= 1 corpus case.
  const coveredRules = new Set<string>()
  for (const c of corpus) {
    const cls = c.proofReceipt?.vulnClass ?? c.canonicalLabel.vulnClass
    if (!cls) continue
    const oobIds = c.proofReceipt?.oobEvents?.map(e => e.id) ?? []
    const { rule } = receiptRuleFor(cls, { oobEventIds: oobIds })
    if (rule !== 'none') coveredRules.add(rule)
  }
  for (const rule of REGISTERED_SINGLE_HOP_RULES) {
    assert.ok(coveredRules.has(rule), `Single-hop oracle rule "${rule}" has zero parity corpus coverage`)
  }

  // Lateral same-CWE permutation over every single-hop FP corpus case with recorded exchanges.
  const fpCases = corpus.filter(
    c =>
      c.side === 'fp' &&
      c.expected.confirmed === false &&
      c.exchanges.length > 0 &&
      (!c.paths.composite || Boolean(c.paths.proofReceipt || c.paths.replay || c.paths.floorReceipt)),
  )
  assert.ok(fpCases.length >= 15, `expected >= 15 single-hop FP corpus cases for lateral sweep, got ${fpCases.length}`)

  let totalPermutations = 0
  const falseConfirms: string[] = []

  for (const c of fpCases) {
    const seedLabel = c.proofReceipt?.vulnClass ?? c.canonicalLabel.vulnClass ?? c.canonicalLabel.cwe
    if (!seedLabel) continue
    const siblings = DEFAULT_ORACLE_SPEC_REGISTRY.sameCweSiblingLabels(seedLabel, 'single_hop')
    if (siblings.length === 0) continue

    const personaMap = new Map(c.personas.map(p => [p.handle, p]))
    const log = new HostFactLog({ signingKey: TEST_SIGNING_KEY })
    const origin = 'https://app.example.test'

    c.exchanges.forEach((ex, idx) => {
      const persona = ex.persona ? personaMap.get(ex.persona) : undefined
      log.recordExchange({
        exchangeId: ex.id,
        seq: idx + 1,
        method: ex.method,
        origin,
        pathAndQuery: ex.pathAndQuery,
        status: ex.status,
        requestHeaders: {
          ...(persona ? { [persona.headerName]: persona.headerValue } : {}),
          ...(ex.requestHeaders ?? {}),
        },
        rawRequestBody: ex.requestJson !== undefined ? JSON.stringify(ex.requestJson) : null,
        responseHeaders: ex.responseHeaders,
        rawResponseBody: ex.body,
        actor: persona?.handle ?? null,
        actorRole: persona?.role ?? null,
        actorTenant: persona?.tenant ?? null,
        ambientAuth: persona?.auth ?? 'unknown',
        arm: ex.arm,
        ...(ex.evidenceRole ? { evidenceRole: ex.evidenceRole } : {}),
        durationMs: ex.durationMs ?? 25,
        timestampMs: 1_700_000_000_000 + (idx + 1) * 100,
        cleanSession: true,
      })
    })

    const targetEx = c.exchanges.find(e => e.arm === 'probe') ?? c.exchanges[0]!
    const transcript = log.toHostSignedTranscript({ signingKey: TEST_SIGNING_KEY })

    for (const sibling of siblings) {
      totalPermutations += 1
      const receipt = buildProofReceipt({
        vulnClass: sibling,
        target: {
          origin,
          method: (c.proofReceipt?.targetMethod ?? targetEx.method).toUpperCase(),
          pathAndQuery: c.proofReceipt?.targetPathAndQuery ?? targetEx.pathAndQuery,
          ...(c.proofReceipt?.param ? { param: c.proofReceipt.param } : {}),
        },
        exchangeIds: c.exchanges.map(e => e.id),
        claimedDelta: `Lateral same-CWE permutation (${c.id} -> ${sibling})`,
      })

      const termRes = evaluateTerminalOracle(log, { kind: 'single_hop', receipt }, { signingKey: TEST_SIGNING_KEY })
      const directRes = verifyReceipt(receipt, { ...transcript, oobSigningKey: TEST_SIGNING_KEY }, { signingKey: TEST_SIGNING_KEY })

      if (termRes.confirmed) {
        falseConfirms.push(`${c.id} -> ${sibling} [evaluateTerminalOracle]: ${termRes.reason}`)
      }
      if (directRes.confirmed) {
        falseConfirms.push(`${c.id} -> ${sibling} [verifyReceipt]: ${directRes.reason}`)
      }
    }
  }

  assert.ok(totalPermutations >= 100, `expected >= 100 lateral same-CWE permutations across FP corpus, ran ${totalPermutations}`)
  assert.deepEqual(falseConfirms, [], `Lateral same-CWE relabeling caused false confirms:\n  - ${falseConfirms.join('\n  - ')}`)
})

// ============================================================================
// 5. verify-claims.ts migrated OracleSpec claim evaluators (timing, oob, structural_diff, race)
// ============================================================================

test('R3-13 verify-claims.ts migrated OracleSpec dispatch evaluates timing, oob, structural_diff, and race accurately', () => {
  const sha = (s: string) => createHash('sha256').update(s).digest('hex')
  const store = new TranscriptStore()

  // Interleaved timing pairs: control ~20ms, variant ~450ms (5 pairs).
  const ctlIds: string[] = []
  const varIds: string[] = []
  for (let i = 0; i < 5; i += 1) {
    const cRec = store.record({
      op: 'http',
      startedAt: 1000 + i * 1000,
      durationMs: 20 + i,
      request: { origin: 'http://127.0.0.1:41999', method: 'GET', pathAndQuery: '/api/items?id=1', headers: {}, bodyBytes: 0, bodySha256: sha(''), nonce: `n-c-${i}` },
      response: { status: 200, headers: { 'content-type': 'application/json' }, bodyBytes: 12, bodySha256: sha('{"rows":[1]}'), mediaType: 'application/json' },
      body: '{"rows":[1]}',
    })
    const vRec = store.record({
      op: 'http',
      startedAt: 1500 + i * 1000,
      durationMs: 450 + i * 10,
      request: { origin: 'http://127.0.0.1:41999', method: 'GET', pathAndQuery: '/api/items?id=2', headers: {}, bodyBytes: 0, bodySha256: sha(''), nonce: `n-v-${i}` },
      response: { status: 200, headers: { 'content-type': 'application/json' }, bodyBytes: 12, bodySha256: sha('{"rows":[1]}'), mediaType: 'application/json' },
      body: '{"rows":[1]}',
    })
    ctlIds.push(cRec.exchangeId)
    varIds.push(vRec.exchangeId)
  }

  const timingOk = evaluateClaims(store, [{ kind: 'timing', controlIds: ctlIds, variantIds: varIds }], {})
  assert.equal(timingOk.passed, true, timingOk.failures.join('; '))

  // Non-interleaved / insufficient timing pairs must fail closed.
  const timingFail = evaluateClaims(store, [{ kind: 'timing', controlIds: ctlIds.slice(0, 2), variantIds: varIds.slice(0, 2) }], {})
  assert.equal(timingFail.passed, false)

  // OOB hit vs miss.
  const oobMint = store.record({
    op: 'oob',
    startedAt: 9000,
    durationMs: 5,
    artifact: { kind: 'oob-mint', token: 'tok_r313_canary_01', hit: false },
  })
  assert.equal(evaluateClaims(store, [{ kind: 'oob', exchangeId: oobMint.exchangeId }], {}).passed, false)
  store.record({
    op: 'oob',
    startedAt: 9500,
    durationMs: 5,
    artifact: { kind: 'oob-mint', token: 'tok_r313_canary_01', hit: true },
  })
  assert.equal(evaluateClaims(store, [{ kind: 'oob', exchangeId: oobMint.exchangeId }], {}).passed, true)

  // Race: idempotent identical outcomes must fail closed; divergent outcomes pass claim check.
  const r1 = store.record({
    op: 'http2',
    startedAt: 10000,
    durationMs: 15,
    request: { origin: 'http://127.0.0.1:41999', method: 'POST', pathAndQuery: '/api/redeem', headers: {}, bodyBytes: 2, bodySha256: sha('{}'), nonce: 'r1' },
    response: { status: 200, headers: {}, bodyBytes: 11, bodySha256: sha('{"ok":true}'), mediaType: 'application/json' },
    body: '{"ok":true}',
  })
  const r2 = store.record({
    op: 'http2',
    startedAt: 10001,
    durationMs: 16,
    request: { origin: 'http://127.0.0.1:41999', method: 'POST', pathAndQuery: '/api/redeem', headers: {}, bodyBytes: 2, bodySha256: sha('{}'), nonce: 'r2' },
    response: { status: 200, headers: {}, bodyBytes: 11, bodySha256: sha('{"ok":true}'), mediaType: 'application/json' },
    body: '{"ok":true}',
  })
  const r3 = store.record({
    op: 'http2',
    startedAt: 10002,
    durationMs: 16,
    request: { origin: 'http://127.0.0.1:41999', method: 'POST', pathAndQuery: '/api/redeem', headers: {}, bodyBytes: 2, bodySha256: sha('{}'), nonce: 'r3' },
    response: { status: 200, headers: {}, bodyBytes: 18, bodySha256: sha('{"redeemed":2}'), mediaType: 'application/json' },
    body: '{"redeemed":2}',
  })
  assert.equal(evaluateClaims(store, [{ kind: 'race', exchangeIds: [r1.exchangeId, r2.exchangeId], mode: 'h2-single-packet' }], {}).passed, false)
  assert.equal(evaluateClaims(store, [{ kind: 'race', exchangeIds: [r1.exchangeId, r3.exchangeId], mode: 'h2-single-packet' }], {}).passed, true)
})
