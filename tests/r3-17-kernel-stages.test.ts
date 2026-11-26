/**
 * R3-17 Kernel Stages — Behavioral, Registry, Budget, and AST Structural Invariants.
 *
 * Verifies all five deliverables of R3-17 without any source-text regex assertions:
 *   1. Single fail-closed carrier normalizer (`src/server/proof-kernel/reflection.ts`) with
 *      explicit malformed-input rejection mode and zero duplicate echo predicates outside it.
 *   2. Single spec-driven `assertLegitimateControl()` stage executing for 100% of specs
 *      declaring a denied control (and preserving legitimate temporal differences on
 *      `v8:temporal_revocation` and tampered-signature controls on `webhook` / crypto replay).
 *   3. Unified budgeted `must_be_non_public` stage executing for 100% of boundary specs
 *      (including `disclosure`, `signed_url_mint`, `v8:dual_tenant_abac`, and
 *      `v8:cryptographic_scope_replay`), bounded by `run-safety-budgets.ts` and strictly
 *      respecting `prod_readonly`.
 *   4. Consolidated boolean-pair concept module (`src/server/proof-kernel/boolean-differential.ts`)
 *      with single `stepToBooleanArm` (no verbatim clone) and handler-side defense-in-depth
 *      `verifyBooleanArmBaseParity` preserved in `src/server/verify-support.ts`.
 */
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import { DEFAULT_ORACLE_SPEC_REGISTRY, type OracleSpec } from '../src/server/oracle-spec.ts'
import {
  normalizeCarrierForAntiReflection,
  type ImpactStep,
} from '../src/server/oracle-invariants.ts'
import {
  MalformedCarrierError,
  buildRequestReflectionIndex,
  carrierEchoesSignedUrlNeedles,
  carrierReflectsExpressionOutput,
  extractSignedUrlNeedlesFromResponse,
  isMatchEchoedFromRequest,
  normalizeRequestCarrier,
} from '../src/server/proof-kernel/reflection.ts'
import {
  assertLegitimateControl,
  specDeclaresDeniedControl,
} from '../src/server/proof-kernel/control-legitimacy.ts'
import {
  PublicnessReplayBudgetLedger,
  evaluateMustBeNonPublicStage,
  specRequiresNonPublic,
} from '../src/server/proof-kernel/publicness.ts'
import {
  assessBooleanDifferential,
  canonicalPredicateSkeleton,
  hasEqualLengthAndCharMultiset,
  stepToBooleanArm,
  verifyBooleanTriangleBinding,
} from '../src/server/proof-kernel/boolean-differential.ts'
import {
  RUN_SAFETY_BUDGET_DEFAULTS,
  RUN_SAFETY_BUDGET_HARD_CEILINGS,
  resolveRunSafetyBudgets,
} from '../src/server/run-safety-budgets.ts'
import { runAllRunDisposers } from '../src/server/run-disposers.ts'
import { TerminalOracleRegistry } from '../src/server/terminal-oracle-registry.ts'
import { verifyBooleanArmBaseParity } from '../src/server/verify-support.ts'
import { TranscriptStore, evaluateClaim } from '../src/server/verify-claims.ts'
import { buildProofReceipt } from '../src/server/proof-receipt.ts'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const SERVER_DIR = join(REPO_ROOT, 'src', 'server')

function collectServerTsFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      out.push(...collectServerTsFiles(full))
    } else if (entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts')) {
      out.push(full)
    }
  }
  return out.sort()
}

function collectDeclaredFunctionNamesByFile(): Map<string, Set<string>> {
  const result = new Map<string, Set<string>>()
  for (const absPath of collectServerTsFiles(SERVER_DIR)) {
    const rel = relative(REPO_ROOT, absPath).replace(/\\/g, '/')
    const text = readFileSync(absPath, 'utf8')
    const sf = ts.createSourceFile(absPath, text, ts.ScriptTarget.ESNext, true)
    const names = new Set<string>()
    const visit = (node: ts.Node) => {
      if (ts.isFunctionDeclaration(node) && node.name) {
        names.add(node.name.text)
      } else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) {
        names.add(node.name.text)
      }
      ts.forEachChild(node, visit)
    }
    visit(sf)
    result.set(rel, names)
  }
  return result
}

test('R3-17 AST structural guard: exactly 1 carrier normalizer, 0 duplicate echo predicates, 0 impactStepToBooleanArm clones', () => {
  const declsByFile = collectDeclaredFunctionNamesByFile()

  const carrierNormalizerDecls: string[] = []
  const echoPredicateNames = new Set([
    'carrierEchoesSignedUrlNeedle',
    'carrierEchoesSignedUrlNeedles',
    'isSignatureOrUrlEchoedFromCarrier',
    'carrierReflectsExpressionOutput',
    'stripRequestEchoes',
    'normalizeEchoText',
    'normalizeEchoComparable',
    'isMatchEchoedFromRequest',
    'isBooleanDifferentialEchoOnly',
  ])
  const echoPredicatesOutsideReflection: string[] = []
  const booleanArmAdapters: string[] = []

  for (const [rel, names] of declsByFile) {
    for (const name of names) {
      if (name === 'normalizeRequestCarrier' || name === 'normalizeCarrierForAntiReflection' || name === 'normalizeSignedUrlExchangeCarrier') {
        carrierNormalizerDecls.push(`${rel}::${name}`)
      }
      if (echoPredicateNames.has(name) && rel !== 'src/server/proof-kernel/reflection.ts') {
        echoPredicatesOutsideReflection.push(`${rel}::${name}`)
      }
      if (name === 'impactStepToBooleanArm' || name === 'stepToBooleanArm') {
        booleanArmAdapters.push(`${rel}::${name}`)
      }
    }
  }

  assert.deepEqual(carrierNormalizerDecls, ['src/server/proof-kernel/reflection.ts::normalizeRequestCarrier'])
  assert.deepEqual(echoPredicatesOutsideReflection, [])
  assert.deepEqual(booleanArmAdapters, ['src/server/proof-kernel/boolean-differential.ts::stepToBooleanArm'])
  assert.equal(normalizeCarrierForAntiReflection, normalizeRequestCarrier, 'oracle-invariants alias must point directly to single canonical normalizer')
})

test('R3-17 reflection: single fail-closed carrier normalizer rejects malformed URL/JSON/unicode inputs', () => {
  // Malformed percent escape flags & throws under malformedMode: 'reject'
  const badPct = normalizeRequestCarrier({ pathAndQuery: '/api/search?q=%41%ZZ' })
  assert.equal(badPct.malformedEscape, true)
  assert.equal(badPct.malformedReason, 'malformed_percent_escape')
  assert.throws(
    () => normalizeRequestCarrier({ pathAndQuery: '/api/search?q=%41%ZZ' }, { malformedMode: 'reject' }),
    MalformedCarrierError,
  )

  // Malformed JSON unicode escape fails closed
  const badUni = normalizeRequestCarrier({
    pathAndQuery: '/api/render',
    requestBody: '{"note":"\\u123g"}',
    requestHeaders: { 'content-type': 'application/json' },
  })
  assert.equal(badUni.malformedEscape, true)
  assert.equal(badUni.malformedReason, 'malformed_unicode_escape')

  // Strict JSON mode is ON by default so malformed JSON bodies fail closed without opting in (R3-17 B3)
  const badJson = normalizeRequestCarrier(
    { pathAndQuery: '/api/items', requestBody: '{"broken":', requestHeaders: { 'content-type': 'application/json' } },
  )
  assert.equal(badJson.malformedJson, true)
  assert.equal(badJson.malformedEscape, true)
  assert.equal(badJson.malformedReason, 'malformed_json_body')

  // Worker-controlled transport headers (User-Agent / Accept-Language) remain in comparables so
  // percent-encoded or case-variant echoes in those headers are caught (R3-17 non-blocking #1)
  const uaSig = '0123456789ABCDEF0123456789ABCDEF'
  const uaCarrier = normalizeRequestCarrier({
    pathAndQuery: '/api/presign',
    requestHeaders: {
      'user-agent': `CustomClient/1.0 %30%31%32%33%34%35%36%37%38%39abcdef0123456789abcdef`,
      'accept-language': 'en-US,en;q=0.9',
    },
  })
  const uaNeedles = extractSignedUrlNeedlesFromResponse({
    responseBody: `https://storage.example.test/bucket/file?X-Goog-Signature=${uaSig}`,
  })
  assert.equal(
    carrierEchoesSignedUrlNeedles(uaCarrier, uaNeedles),
    true,
    'percent-encoded/case-variant signature echoed in User-Agent must be caught',
  )

  // Every echo predicate fails closed (returns true = treated as echoed) on malformed carriers
  assert.equal(
    carrierReflectsExpressionOutput(badPct, { operandA: 131, operandB: 257, operator: '*', expectedOutput: '33667' }),
    true,
  )
  assert.equal(
    carrierEchoesSignedUrlNeedles(badUni, ['https://storage.example.test/bucket/file?X-Goog-Signature=0123456789abcdef0123456789abcdef']),
    true,
  )
  const badIndex = buildRequestReflectionIndex({ pathAndQuery: '/api/q?x=%ZZ' })
  assert.equal(isMatchEchoedFromRequest(badIndex, 'benign_marker_token'), true)

  // Deletion-normalized reflection catches zero-width & HTML-tag split echoes
  const cleanIdx = buildRequestReflectionIndex({ pathAndQuery: '/api/q?x=marker<b>\u200Btoken</b>' })
  assert.equal(cleanIdx.malformedEscape, false)
  assert.equal(isMatchEchoedFromRequest(cleanIdx, 'markertoken'), true)
})

function buildFactLogForSpec(spec: OracleSpec, opts: { sabotagedControl?: boolean; anonymousPublic?: boolean } = {}): {
  factLog: HostFactLog
  controlId: string
  probeId: string
  anonId?: string
} {
  const factLog = new HostFactLog()
  const baseHeaders: Record<string, string> = opts.sabotagedControl
    ? { authorization: 'Bearer kovo-synth-invalid-r317' }
    : {}
  const ctlAnon = spec.id === 'auth_bypass' || (spec.id === 'impact:signed_url_mint' && !opts.anonymousPublic)
  const ctlFact = factLog.recordExchange({
    exchangeId: `ex-ctl-${spec.id.replace(/[^a-z0-9]/gi, '_')}`,
    origin: 'https://target.test',
    method: 'GET',
    pathAndQuery: '/api/protected/records/42',
    status: spec.id === 'impact:signed_url_mint' && opts.anonymousPublic ? 200 : 401,
    arm: 'control',
    actor: ctlAnon ? null : (spec.id === 'impact:signed_url_mint' ? 'member_a' : 'viewer_b'),
    actorRole: ctlAnon ? null : (spec.id === 'impact:signed_url_mint' ? 'member' : 'viewer'),
    actorTenant: ctlAnon ? null : (spec.id === 'impact:signed_url_mint' ? 'tenant-a' : 'tenant-b'),
    ambientAuth: ctlAnon ? 'unknown' : 'bearer',
    requestHeaders: baseHeaders,
    rawResponseBody: JSON.stringify({ error: 'denied' }),
    responseHeaders: { 'content-type': 'application/json' },
    timestampMs: 1_700_000_001_000,
    ...(opts.sabotagedControl ? {
      wireCredentialProvenance: {
        authenticated: false,
        authMutated: true,
        source: 'none',
        sources: [],
        personaHandle: null,
        session: null,
        headerNames: ['authorization'],
        callerAuthHeaderNames: ['authorization'],
        vaultHeaderNames: [],
        cookieNames: [],
        vaultCookieNames: [],
        jarCookieNames: [],
      },
    } : {}),
  })
  const prbAnon = spec.id === 'auth_bypass'
  const prbFact = factLog.recordExchange({
    exchangeId: `ex-prb-${spec.id.replace(/[^a-z0-9]/gi, '_')}`,
    origin: 'https://target.test',
    method: 'GET',
    pathAndQuery: '/api/protected/records/42',
    status: 200,
    arm: 'probe',
    actor: prbAnon ? null : 'member_a',
    actorRole: prbAnon ? null : 'member',
    actorTenant: prbAnon ? null : 'tenant-a',
    ambientAuth: prbAnon ? 'unknown' : 'bearer',
    requestHeaders: prbAnon ? { 'x-forwarded-user': 'ops' } : {},
    rawResponseBody: JSON.stringify({ id: '42', title: 'Public catalog summary', region: 'us-east' }),
    responseHeaders: { 'content-type': 'application/json' },
    timestampMs: 1_700_000_002_000,
  })
  let anonId: string | undefined
  if (opts.anonymousPublic) {
    const anonFact = factLog.recordExchange({
      exchangeId: `ex-anon-${spec.id.replace(/[^a-z0-9]/gi, '_')}`,
      origin: 'https://target.test',
      method: 'GET',
      pathAndQuery: '/api/protected/records/42',
      status: 200,
      arm: 'control',
      actor: null,
      actorRole: null,
      actorTenant: null,
      ambientAuth: 'unknown',
      rawResponseBody: JSON.stringify({ id: '42', title: 'Public catalog summary', region: 'us-east' }),
      responseHeaders: { 'content-type': 'application/json' },
      timestampMs: 1_700_000_003_000,
    })
    anonId = anonFact.exchangeId
  }
  return { factLog, controlId: ctlFact.exchangeId, probeId: prbFact.exchangeId, anonId }
}

function buildV8RawInputForSpec(family: string, controlId: string, probeId: string): Record<string, unknown> {
  if (family === 'dual_tenant_abac') {
    return { mode: 'dual_org_cache_bleed', baselineDeniedControl: controlId, primeAction: probeId, bledAccess: probeId }
  }
  if (family === 'temporal_revocation') {
    return { credentialKind: 'token', preRevocationBaseline: probeId, revocationEvent: controlId, primaryDeniedCheck: controlId, secondarySuccess: probeId }
  }
  if (family === 'cryptographic_scope_replay') {
    return { tamperedSignatureControl: controlId, sourceValidIssuance: probeId, replayedAcceptance: probeId }
  }
  if (family === 'cross_surface_pivot') {
    return { hops: [{ hopId: 'h1', role: 'terminal', record: probeId }], terminalImpact: { kind: 'cross_tenant_read', postImpactReadback: probeId } }
  }
  return {}
}

test('R3-17 registry coverage: assertLegitimateControl executes for 100% of specs declaring a denied control', () => {
  const registry = new TerminalOracleRegistry()
  const deniedSpecs = DEFAULT_ORACLE_SPEC_REGISTRY.list().filter(specDeclaresDeniedControl)
  assert.ok(deniedSpecs.length >= 10, `expected >= 10 denied-control specs, got ${deniedSpecs.length}`)

  const executedSpecIds = new Set<string>()
  for (const spec of deniedSpecs) {
    const { factLog, controlId, probeId } = buildFactLogForSpec(spec, { sabotagedControl: true })
    const onKernelStageExecuted = (ev: { stage: string; specId: string; ok: boolean }) => {
      if (ev.stage === 'control_legitimacy') executedSpecIds.add(ev.specId)
    }
    if (spec.kind === 'single_hop') {
      const receipt = buildProofReceipt({
        vulnClass: spec.canonicalVulnClass,
        target: { origin: 'https://target.test', method: 'GET', pathAndQuery: '/api/protected/records/42' },
        exchangeIds: [controlId, probeId],
        claimedDelta: 'Synthetic test delta',
      })
      const res = registry.evaluate(factLog, { kind: 'single_hop', receipt }, { onKernelStageExecuted })
      assert.equal(res.confirmed, false, `sabotaged control must reject for ${spec.id}`)
    } else if (spec.v8Family) {
      const res = registry.evaluate(
        factLog,
        { kind: 'v8_family', family: spec.v8Family, rawInput: buildV8RawInputForSpec(spec.v8Family, controlId, probeId) },
        { onKernelStageExecuted },
      )
      assert.equal(res.confirmed, false, `sabotaged control must reject for ${spec.id}`)
    }
  }

  assert.equal(
    executedSpecIds.size,
    deniedSpecs.length,
    `control_legitimacy must execute for every denied-control spec (missing: ${deniedSpecs.filter(s => !executedSpecIds.has(s.id)).map(s => s.id).join(', ')})`,
  )
})

test('R3-17 control legitimacy: preserves v8:temporal_revocation time difference & rejects self-sabotage in evaluateClaim', () => {
  const temporalSpec = DEFAULT_ORACLE_SPEC_REGISTRY.get('v8:temporal_revocation')!
  const cleanTemporal = assertLegitimateControl({
    spec: temporalSpec,
    control: {
      id: 'ex-primary-denied',
      method: 'GET',
      route: '/api/session/me',
      status: 401,
      actorHandle: 'member_a',
      actorRole: 'member',
      requestHeaders: { authorization: 'Bearer revoked-session-token-123' },
      timestampMs: 1_700_000_010_000,
    },
    probe: {
      id: 'ex-secondary-ok',
      method: 'GET',
      route: '/api/session/me',
      status: 200,
      actorHandle: 'member_a',
      actorRole: 'member',
      requestHeaders: { authorization: 'Bearer revoked-session-token-123' },
      timestampMs: 1_700_000_020_000,
    },
  })
  assert.equal(cleanTemporal.ok, true, 'v8:temporal_revocation legitimate post-revocation time difference must be preserved')
  assert.equal(cleanTemporal.contractRole, 'denied_revoked')

  // R1: temporal_revocation MUST NOT relax route parity when control hits a different route
  const wrongRouteTemporal = assertLegitimateControl({
    spec: temporalSpec,
    control: {
      id: 'ex-primary-wrong-route',
      method: 'GET',
      route: '/api/admin/revoked',
      status: 401,
      actorHandle: 'member_a',
      actorRole: 'member',
      timestampMs: 1_700_000_010_000,
    },
    probe: {
      id: 'ex-secondary-ok',
      method: 'GET',
      route: '/api/session/me',
      status: 200,
      actorHandle: 'member_a',
      actorRole: 'member',
      timestampMs: 1_700_000_020_000,
    },
  })
  assert.equal(wrongRouteTemporal.ok, false)
  assert.equal(wrongRouteTemporal.rejectedBy, 'self_sabotaged_control')

  // Self-sabotaged control on temporal revocation MUST reject
  const sabotagedTemporal = assertLegitimateControl({
    spec: temporalSpec,
    control: {
      id: 'ex-primary-sabotaged',
      method: 'GET',
      route: '/api/session/me',
      status: 401,
      requestHeaders: { authorization: 'Bearer kovo-synth-invalid-temporal' },
      timestampMs: 1_700_000_010_000,
    },
    probe: {
      id: 'ex-secondary-ok',
      method: 'GET',
      route: '/api/session/me',
      status: 200,
      timestampMs: 1_700_000_020_000,
    },
  })
  assert.equal(sabotagedTemporal.ok, false)
  assert.equal(sabotagedTemporal.rejectedBy, 'self_sabotaged_control')

  // evaluateClaim('boundary') delegates to assertLegitimateControl()
  const store = new TranscriptStore()
  const ctlRec = store.record({
    op: 'http',
    startedAt: 1_700_000_001_000,
    durationMs: 10,
    request: { origin: 'http://target.test', method: 'GET', pathAndQuery: '/api/admin/settings', sessionRole: 'control', headers: { authorization: 'Bearer kovo-synth-invalid-boundary' }, bodyBytes: 0, bodySha256: '0'.repeat(64), nonce: 'n1' },
    response: { status: 401, mediaType: 'application/json', headers: { 'content-type': 'application/json' }, bodyBytes: 24, bodySha256: 'a'.repeat(64) },
    body: '{"error":"unauthorized"}',
  })
  const prbRec = store.record({
    op: 'http',
    startedAt: 1_700_000_002_000,
    durationMs: 10,
    request: { origin: 'http://target.test', method: 'GET', pathAndQuery: '/api/admin/settings', sessionRole: 'probe', headers: { 'x-forwarded-user': 'ops' }, bodyBytes: 0, bodySha256: '0'.repeat(64), nonce: 'n2' },
    response: { status: 200, mediaType: 'application/json', headers: { 'content-type': 'application/json' }, bodyBytes: 29, bodySha256: 'b'.repeat(64) },
    body: '{"settings":{"mode":"open"}}',
  })
  const check = evaluateClaim(store, { kind: 'boundary', boundaryClass: 'auth', controlExchangeId: ctlRec.exchangeId, probeExchangeId: prbRec.exchangeId }, {})
  assert.equal(check.passed, false)
  assert.equal((check.observed as { rejectedBy?: string } | undefined)?.rejectedBy, 'self_sabotaged_control')
})

test('R3-17 publicness stage: executes for 100% of boundary specs and closes disclosure, signed_url_mint, v8 dual-tenant & crypto gaps', () => {
  const registry = new TerminalOracleRegistry()
  const boundarySpecs = DEFAULT_ORACLE_SPEC_REGISTRY.list().filter(specRequiresNonPublic)
  const expectedIds = [
    'impact:authorization',
    'impact:signed_url_mint',
    'impact:bfla',
    'impact:disclosure',
    'auth_bypass',
    'v8:dual_tenant_abac',
    'v8:temporal_revocation',
    'v8:cryptographic_scope_replay',
    'v8:cross_surface_pivot',
  ]
  for (const id of expectedIds) {
    assert.ok(boundarySpecs.some(s => s.id === id), `expected boundary spec ${id} to require non-publicness`)
  }

  const executedSpecIds = new Set<string>()
  const rejectedSpecIds = new Set<string>()
  for (const spec of boundarySpecs) {
    const onKernelStageExecuted = (ev: { stage: string; specId: string; ok: boolean }) => {
      if (ev.stage === 'must_be_non_public') {
        executedSpecIds.add(ev.specId)
        if (!ev.ok) rejectedSpecIds.add(ev.specId)
      }
    }
    // 1. Clean non-public control pair ensures control_legitimacy passes and must_be_non_public executes for 100% of boundary specs
    const clean = buildFactLogForSpec(spec, { anonymousPublic: false })
    if (spec.kind === 'single_hop') {
      const receipt = buildProofReceipt({
        vulnClass: spec.canonicalVulnClass,
        target: { origin: 'https://target.test', method: 'GET', pathAndQuery: '/api/protected/records/42' },
        exchangeIds: [clean.controlId, clean.probeId],
        claimedDelta: 'Non-public control pair exercises must_be_non_public stage',
      })
      registry.evaluate(clean.factLog, { kind: 'single_hop', receipt }, { onKernelStageExecuted })
    } else if (spec.v8Family) {
      registry.evaluate(
        clean.factLog,
        { kind: 'v8_family', family: spec.v8Family, rawInput: buildV8RawInputForSpec(spec.v8Family, clean.controlId, clean.probeId) },
        { onKernelStageExecuted },
      )
    }

    // 2. Anonymous 200 public surface MUST reject for 100% of boundary specs
    const { factLog, controlId, probeId, anonId } = buildFactLogForSpec(spec, { anonymousPublic: true })
    if (spec.kind === 'single_hop') {
      const receipt = buildProofReceipt({
        vulnClass: spec.canonicalVulnClass,
        target: { origin: 'https://target.test', method: 'GET', pathAndQuery: '/api/protected/records/42' },
        exchangeIds: [controlId, probeId, ...(anonId ? [anonId] : [])],
        claimedDelta: 'Public catalog read should dismiss',
      })
      const res = registry.evaluate(factLog, { kind: 'single_hop', receipt }, { onKernelStageExecuted })
      assert.equal(res.confirmed, false, `public surface must reject for ${spec.id}`)
    } else if (spec.v8Family) {
      const res = registry.evaluate(
        factLog,
        { kind: 'v8_family', family: spec.v8Family, rawInput: buildV8RawInputForSpec(spec.v8Family, controlId, probeId) },
        { onKernelStageExecuted },
      )
      assert.equal(res.confirmed, false, `public surface must reject for ${spec.id}`)
    }
  }

  assert.equal(executedSpecIds.size, boundarySpecs.length, `must_be_non_public must execute for 100% of boundary specs (missing: ${boundarySpecs.filter(s => !executedSpecIds.has(s.id)).map(s => s.id).join(', ')})`)
  for (const closedGapId of ['impact:disclosure', 'impact:signed_url_mint', 'v8:dual_tenant_abac', 'v8:cryptographic_scope_replay']) {
    assert.ok(rejectedSpecIds.has(closedGapId), `must_be_non_public must actively reject anonymous 200 public access on ${closedGapId}`)
  }
})

test('R3-17 publicness budget & prod_readonly policy: enforces run-safety-budgets caps with structured truncation telemetry', () => {
  const defaults = resolveRunSafetyBudgets()
  assert.equal(defaults.maxPublicnessReplaysPerRun, RUN_SAFETY_BUDGET_DEFAULTS.maxPublicnessReplaysPerRun)
  assert.equal(defaults.maxPublicnessReplaysPerRoute, RUN_SAFETY_BUDGET_DEFAULTS.maxPublicnessReplaysPerRoute)

  const clamped = resolveRunSafetyBudgets({
    overrides: { maxPublicnessReplaysPerRun: 999_999, maxPublicnessReplaysPerRoute: 999 },
  })
  assert.equal(clamped.maxPublicnessReplaysPerRun, RUN_SAFETY_BUDGET_HARD_CEILINGS.maxPublicnessReplaysPerRun)
  assert.equal(clamped.maxPublicnessReplaysPerRoute, RUN_SAFETY_BUDGET_HARD_CEILINGS.maxPublicnessReplaysPerRoute)

  const ledger = new PublicnessReplayBudgetLedger({ maxPerRun: 3, maxPerRoute: 2 })

  // prod_readonly strictly refuses mutating POST/PUT/DELETE publicness probes
  const refusedPost = ledger.admit({ runId: 'run-budget-1', method: 'POST', route: '/api/orders', environmentMode: 'prod_readonly' })
  assert.equal(refusedPost.allowed, false)
  assert.equal(refusedPost.skippedReason, 'prod_readonly_non_read_method')
  assert.equal(refusedPost.runCount, 0)

  // Read-only GET is admitted up to per-route cap (2), then truncates on 3rd attempt on same route
  const g1 = ledger.admit({ runId: 'run-budget-1', method: 'GET', route: '/api/items/1', environmentMode: 'prod_readonly' })
  const g2 = ledger.admit({ runId: 'run-budget-1', method: 'GET', route: '/api/items/1', environmentMode: 'prod_readonly' })
  const g3 = ledger.admit({ runId: 'run-budget-1', method: 'GET', route: '/api/items/1', environmentMode: 'prod_readonly' })
  assert.equal(g1.allowed, true)
  assert.equal(g2.allowed, true)
  assert.equal(g3.allowed, false)
  assert.equal(g3.truncated, true)
  assert.equal(g3.skippedReason, 'budget_exhausted_route')

  // Another route consumes the 3rd and final run slot; 4th overall truncates on run cap
  const g4 = ledger.admit({ runId: 'run-budget-1', method: 'HEAD', route: '/api/items/2', environmentMode: 'prod_readonly' })
  const g5 = ledger.admit({ runId: 'run-budget-1', method: 'GET', route: '/api/items/3', environmentMode: 'prod_readonly' })
  assert.equal(g4.allowed, true)
  assert.equal(g5.allowed, false)
  assert.equal(g5.truncated, true)
  assert.equal(g5.skippedReason, 'budget_exhausted_run')
  assert.equal(ledger.getRunUsage('run-budget-1'), 3)

  // Wired through evaluateMustBeNonPublicStage emits replayTelemetry
  const stageRes = evaluateMustBeNonPublicStage({
    spec: DEFAULT_ORACLE_SPEC_REGISTRY.get('impact:disclosure')!,
    steps: [],
    probe: {
      id: 'p1',
      arm: 'probe',
      method: 'POST',
      route: '/api/export',
      status: 200,
      actor: { handle: 'member_a', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null },
      json: { export: 'ok' },
    },
    replayBudget: ledger,
    runId: 'run-budget-1',
    environmentMode: 'prod_readonly',
  })
  assert.equal(stageRes.replayTelemetry?.allowed, false)
  assert.equal(stageRes.replayTelemetry?.skippedReason, 'prod_readonly_non_read_method')
})

test('R3-17 boolean-differential consolidation: preserves TP/FP parity and handler-side verifyBooleanArmBaseParity', () => {
  assert.equal(hasEqualLengthAndCharMultiset('42 AND 317=317', '42 AND 317=713'), true)
  assert.equal(hasEqualLengthAndCharMultiset('42 AND 1=1', '42 AND 1=100'), false)

  // Handler-side defense-in-depth wrapper stays intact
  const parityOk = verifyBooleanArmBaseParity({
    baselineValue: '42',
    controlValue: '42 AND 317=317',
    variantValue: '42 AND 317=713',
  })
  assert.equal(parityOk.ok, true)
  const parityBad = verifyBooleanArmBaseParity({
    baselineValue: '42',
    controlValue: '42 AND 1=1',
    variantValue: '99 AND 1=2',
  })
  assert.equal(parityBad.ok, false)

  // Single stepToBooleanArm + triangle binding + multi-round assessBooleanDifferential
  const makeStep = (id: string, arm: ImpactStep['arm'], val: string, count: number): ImpactStep => ({
    id,
    arm,
    method: 'GET',
    route: '/api/catalog',
    pathAndQuery: `/api/catalog?id=${encodeURIComponent(val)}`,
    status: 200,
    actor: { handle: 'member_a', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null },
    json: { rows: Array.from({ length: count }, (_, idx) => ({ item: idx + 1 })) },
  })
  const baseArm = stepToBooleanArm(makeStep('b1', 'control', '42', 2))
  const trueArm = stepToBooleanArm(makeStep('t1', 'control', '42 AND 317=317', 2))
  const falseArm = stepToBooleanArm(makeStep('f1', 'probe', '42 AND 317=713', 0))

  const skel = canonicalPredicateSkeleton('42 AND 317=317')
  assert.ok(skel && skel.baseValue === '42' && skel.truth === true)

  const tri = verifyBooleanTriangleBinding({ baseline: baseArm, armA: trueArm, armB: falseArm, param: 'id', requireNamedParam: true })
  assert.equal(tri.ok, true)
  assert.equal(tri.trueArm, 'armA')

  const tpAssessment = assessBooleanDifferential({
    param: 'id',
    rounds: [
      { baseline: baseArm, control: trueArm, probe: falseArm },
      { baseline: baseArm, control: trueArm, probe: falseArm },
    ],
  })
  assert.equal(tpAssessment.satisfied, true, tpAssessment.reason)

  // Echoed-only difference still rejects with echoedOnly=true
  const echoTrue = stepToBooleanArm({
    id: 'et1', arm: 'control', method: 'GET', route: '/api/echo', pathAndQuery: '/api/echo?id=item42%20AND%20317%3D317',
    status: 200, actor: { handle: 'member_a', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null },
    json: { id: 'item42 AND 317=317', status: 'ok' },
  })
  const echoFalse = stepToBooleanArm({
    id: 'ef1', arm: 'probe', method: 'GET', route: '/api/echo', pathAndQuery: '/api/echo?id=item42%20AND%20317%3D713',
    status: 200, actor: { handle: 'member_a', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null },
    json: { id: 'echoed-item42 AND 317=713-padded-beyond-short-bucket', status: 'ok' },
  })
  const echoBase = stepToBooleanArm({
    id: 'eb1', arm: 'control', method: 'GET', route: '/api/echo', pathAndQuery: '/api/echo?id=item42',
    status: 200, actor: { handle: 'member_a', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null },
    json: { id: 'item42', status: 'ok' },
  })
  const fpEcho = assessBooleanDifferential({
    param: 'id',
    rounds: [
      { baseline: echoBase, control: echoTrue, probe: echoFalse },
      { baseline: echoBase, control: echoTrue, probe: echoFalse },
    ],
  })
  assert.equal(fpEcho.satisfied, false)
  assert.equal(fpEcho.evidence.echoedOnly, true)
})

test('R3-17 review guards (B1/B1b/B2): differsOnlyIn parity, fail-closed registry stages, non-read signed-URL publicness & run disposer', () => {
  const authBypassSpec = DEFAULT_ORACLE_SPEC_REGISTRY.get('auth_bypass')!
  const authzSpec = DEFAULT_ORACLE_SPEC_REGISTRY.get('impact:authorization')!
  const signedUrlSpec = DEFAULT_ORACLE_SPEC_REGISTRY.get('impact:signed_url_mint')!
  assert.equal(specDeclaresDeniedControl(authBypassSpec), true, 'auth_bypass must declare a denied-control contract')
  assert.equal(specDeclaresDeniedControl(authzSpec), true, 'impact:authorization must declare a denied-control contract')

  // B1: Exact r3-17-claude-bypass-review-fp scenario rejects directly in assertLegitimateControl with self_sabotaged_control
  const reviewFpRes = assertLegitimateControl({
    spec: authzSpec,
    control: {
      id: 'ctl_wrong_path',
      method: 'GET',
      route: '/api/admin/orders/ord-a-1',
      pathAndQuery: '/api/admin/orders/ord-a-1?filter=%zz',
      status: 403,
      actorHandle: 'member_b',
      actorRole: 'member',
      actorAuth: 'bearer',
    },
    probe: {
      id: 'prb_own_record',
      method: 'GET',
      route: '/api/orders/ord-a-1',
      pathAndQuery: '/api/orders/ord-a-1',
      status: 200,
      actorHandle: 'member_a',
      actorRole: 'member',
      actorAuth: 'bearer',
    },
  })
  assert.equal(reviewFpRes.ok, false)
  assert.equal(reviewFpRes.rejectedBy, 'self_sabotaged_control')

  // B1: Even without malformed %zz, sibling admin path, extra query param, method mismatch, or extra body field all reject
  const wrongPathOnly = assertLegitimateControl({
    spec: authzSpec,
    control: { id: 'c1', method: 'GET', pathAndQuery: '/api/admin/orders/ord-a-1', status: 403, actorHandle: 'member_b' },
    probe: { id: 'p1', method: 'GET', pathAndQuery: '/api/orders/ord-a-1', status: 200, actorHandle: 'member_a' },
  })
  assert.equal(wrongPathOnly.ok, false)
  assert.equal(wrongPathOnly.rejectedBy, 'self_sabotaged_control')

  const extraQueryOnly = assertLegitimateControl({
    spec: authzSpec,
    control: { id: 'c2', method: 'GET', pathAndQuery: '/api/orders/ord-a-1?filter=broken', status: 403, actorHandle: 'member_b' },
    probe: { id: 'p2', method: 'GET', pathAndQuery: '/api/orders/ord-a-1', status: 200, actorHandle: 'member_a' },
  })
  assert.equal(extraQueryOnly.ok, false)
  assert.equal(extraQueryOnly.rejectedBy, 'self_sabotaged_control')

  const wrongMethod = assertLegitimateControl({
    spec: authzSpec,
    control: { id: 'c3', method: 'DELETE', pathAndQuery: '/api/orders/ord-a-1', status: 405, actorHandle: 'member_b' },
    probe: { id: 'p3', method: 'GET', pathAndQuery: '/api/orders/ord-a-1', status: 200, actorHandle: 'member_a' },
  })
  assert.equal(wrongMethod.ok, false)
  assert.equal(wrongMethod.rejectedBy, 'self_sabotaged_control')

  const extraBodyKey = assertLegitimateControl({
    spec: authzSpec,
    control: { id: 'c4', method: 'POST', pathAndQuery: '/api/orders/export', status: 403, actorHandle: 'member_b', requestJson: { id: 'ord-1', sabotage: true } },
    probe: { id: 'p4', method: 'POST', pathAndQuery: '/api/orders/export', status: 200, actorHandle: 'member_a', requestJson: { id: 'ord-1' } },
  })
  assert.equal(extraBodyKey.ok, false)
  assert.equal(extraBodyKey.rejectedBy, 'self_sabotaged_control')

  // R1: v8:dual_tenant_abac control on a different route template MUST be rejected with self_sabotaged_control
  //     (request_payload relaxes body-shape parity ONLY, never route/method/query parity)
  const dualTenantSpec = DEFAULT_ORACLE_SPEC_REGISTRY.get('v8:dual_tenant_abac')!
  const dualTenantWrongRoute = assertLegitimateControl({
    spec: dualTenantSpec,
    control: {
      id: 'dt-ctl-wrong-route',
      method: 'GET',
      route: '/api/admin/orders/ord-a-1',
      pathAndQuery: '/api/admin/orders/ord-a-1',
      status: 403,
      actorHandle: 'member_b',
      actorRole: 'member',
    },
    probe: {
      id: 'dt-prb-orders',
      method: 'GET',
      route: '/api/orders/ord-a-1',
      pathAndQuery: '/api/orders/ord-a-1',
      status: 200,
      actorHandle: 'member_a',
      actorRole: 'member',
    },
  })
  assert.equal(dualTenantWrongRoute.ok, false, 'v8:dual_tenant_abac control on a different route template must fail closed')
  assert.equal(dualTenantWrongRoute.rejectedBy, 'self_sabotaged_control')

  // R1: v8:dual_tenant_abac still permits body-shape differences on the SAME route template
  const dualTenantBodyDiffOk = assertLegitimateControl({
    spec: dualTenantSpec,
    control: {
      id: 'dt-ctl-body',
      method: 'POST',
      route: '/api/orders/export',
      status: 403,
      actorHandle: 'member_b',
      requestJson: { singleId: 'ord-a-1' },
    },
    probe: {
      id: 'dt-prb-body',
      method: 'POST',
      route: '/api/orders/export',
      status: 200,
      actorHandle: 'member_a',
      requestJson: { batchIds: ['ord-a-1', 'ord-b-1'] },
    },
  })
  assert.equal(dualTenantBodyDiffOk.ok, true, dualTenantBodyDiffOk.reason)

  // B1: Legitimate same-template sibling BOLA control (differs only in persona/tenant + resource ID) PASSES
  const legitBola = assertLegitimateControl({
    spec: authzSpec,
    control: { id: 'c-ok', method: 'GET', pathAndQuery: '/api/orders/ord-a-1', status: 403, actorHandle: 'member_b' },
    probe: { id: 'p-ok', method: 'GET', pathAndQuery: '/api/orders/ord-b-2', status: 200, actorHandle: 'member_a' },
  })
  assert.equal(legitBola.ok, true, legitBola.reason)

  // B1b: Registry rejects single-hop with zero controls, rejects sabotaged 405 alongside clean 403, and rejects v8 with zero controls
  const registry = new TerminalOracleRegistry()
  const noCtrlLog = new HostFactLog()
  const onlyProbe = noCtrlLog.recordExchange({
    exchangeId: 'ex-only-probe',
    origin: 'https://target.test',
    method: 'GET',
    pathAndQuery: '/api/orders/ord-a-1',
    status: 200,
    arm: 'probe',
    actor: 'member_a',
    actorRole: 'member',
    actorTenant: 'tenant-a',
    ambientAuth: 'bearer',
    rawResponseBody: JSON.stringify({ id: 'ord-a-1', tenant: 'tenant-a' }),
    responseHeaders: { 'content-type': 'application/json' },
    timestampMs: 1_700_000_001_000,
  })
  const noCtrlEvents: Array<{ stage: string; ok: boolean }> = []
  const noCtrlRes = registry.evaluate(
    noCtrlLog,
    {
      kind: 'single_hop',
      receipt: buildProofReceipt({
        vulnClass: 'bola',
        target: { origin: 'https://target.test', method: 'GET', pathAndQuery: '/api/orders/ord-a-1' },
        exchangeIds: [onlyProbe.exchangeId],
        claimedDelta: 'Missing control must fail closed',
      }),
    },
    { onKernelStageExecuted: ev => noCtrlEvents.push({ stage: ev.stage, ok: ev.ok }) },
  )
  assert.equal(noCtrlRes.confirmed, false)
  assert.equal((noCtrlRes.evidence as { rejectedBy?: string } | undefined)?.rejectedBy, 'missing_negative_control')
  assert.ok(noCtrlEvents.some(e => e.stage === 'control_legitimacy' && e.ok === false))

  const v8NoCtrlEvents: Array<{ stage: string; ok: boolean }> = []
  const v8NoCtrlRes = registry.evaluate(
    noCtrlLog,
    { kind: 'v8_family', family: 'dual_tenant_abac', rawInput: { mode: 'dual_org_cache_bleed', bledAccess: onlyProbe.exchangeId } },
    { onKernelStageExecuted: ev => v8NoCtrlEvents.push({ stage: ev.stage, ok: ev.ok }) },
  )
  assert.equal(v8NoCtrlRes.confirmed, false)
  assert.equal((v8NoCtrlRes.evidence as { rejectedBy?: string } | undefined)?.rejectedBy, 'missing_negative_control')
  assert.ok(v8NoCtrlEvents.some(e => e.stage === 'control_legitimacy' && e.ok === false))

  // B1b(c): Single-hop with clean 403 + sabotaged 405 control still checks and rejects the 405 control
  const mixedCtrlLog = new HostFactLog()
  const clean403 = mixedCtrlLog.recordExchange({
    exchangeId: 'ex-c-403',
    origin: 'https://target.test',
    method: 'GET',
    pathAndQuery: '/api/orders/ord-a-1',
    status: 403,
    arm: 'control',
    actor: 'member_b',
    actorRole: 'member',
    actorTenant: 'tenant-b',
    ambientAuth: 'bearer',
    rawResponseBody: '{"error":"forbidden"}',
    responseHeaders: { 'content-type': 'application/json' },
    timestampMs: 1_700_000_001_000,
  })
  const bad405 = mixedCtrlLog.recordExchange({
    exchangeId: 'ex-c-405',
    origin: 'https://target.test',
    method: 'DELETE',
    pathAndQuery: '/api/orders/ord-a-1',
    status: 405,
    arm: 'control',
    actor: 'member_b',
    actorRole: 'member',
    actorTenant: 'tenant-b',
    ambientAuth: 'bearer',
    rawResponseBody: '{"error":"method not allowed"}',
    responseHeaders: { 'content-type': 'application/json' },
    timestampMs: 1_700_000_002_000,
  })
  const probeOk = mixedCtrlLog.recordExchange({
    exchangeId: 'ex-p-200',
    origin: 'https://target.test',
    method: 'GET',
    pathAndQuery: '/api/orders/ord-a-1',
    status: 200,
    arm: 'probe',
    actor: 'member_a',
    actorRole: 'member',
    actorTenant: 'tenant-a',
    ambientAuth: 'bearer',
    rawResponseBody: '{"id":"ord-a-1","tenant":"tenant-a"}',
    responseHeaders: { 'content-type': 'application/json' },
    timestampMs: 1_700_000_003_000,
  })
  const mixedRes = registry.evaluate(mixedCtrlLog, {
    kind: 'single_hop',
    receipt: buildProofReceipt({
      vulnClass: 'bola',
      target: { origin: 'https://target.test', method: 'GET', pathAndQuery: '/api/orders/ord-a-1' },
      exchangeIds: [clean403.exchangeId, bad405.exchangeId, probeOk.exchangeId],
      claimedDelta: 'Mixed clean 403 and sabotaged 405 control',
    }),
  })
  assert.equal(mixedRes.confirmed, false)
  assert.equal((mixedRes.evidence as { rejectedBy?: string } | undefined)?.rejectedBy, 'self_sabotaged_control')

  // B2a: evaluateMustBeNonPublicStage with probe: null MUST fail closed
  const nullProbePub = evaluateMustBeNonPublicStage({ spec: authzSpec, steps: [], probe: null })
  assert.equal(nullProbePub.passed, false, 'must_be_non_public must fail closed when probe is null')

  // B2c: Bare-anonymous POST mint 2xx with a DISTINCT signed-URL body on impact:signed_url_mint MUST reject as public
  const mintProbe: ImpactStep = {
    id: 'mint-prb',
    arm: 'probe',
    method: 'POST',
    route: '/api/storage/presign',
    pathAndQuery: '/api/storage/presign',
    status: 200,
    actor: { handle: 'member_a', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null },
    json: { signedUrl: 'https://storage.example.test/bucket/a?X-Goog-Signature=aaaaaaaaaaaaaaaa1111111111111111' },
  }
  const bareAnonMint: ImpactStep = {
    id: 'mint-anon',
    arm: 'control',
    method: 'POST',
    route: '/api/storage/presign',
    pathAndQuery: '/api/storage/presign',
    status: 200,
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    json: { signedUrl: 'https://storage.example.test/bucket/b?X-Goog-Signature=bbbbbbbbbbbbbbbb2222222222222222' },
  }
  const signedMintPub = evaluateMustBeNonPublicStage({
    spec: signedUrlSpec,
    steps: [bareAnonMint, mintProbe],
    probe: mintProbe,
  })
  assert.equal(signedMintPub.passed, false, 'bare-anon POST mint 2xx with distinct signed URL must reject as public')
  assert.equal(signedMintPub.public, true)
  assert.equal(signedMintPub.referenceId, 'mint-anon')

  // B2b: Active replay gating defaults failClosedOnReplayDenied=true when replayProbe is supplied + run-disposer eviction + empty runId rejection
  const activeLedger = new PublicnessReplayBudgetLedger({ maxPerRun: 2, maxPerRoute: 1 })
  assert.equal(activeLedger.admit({ runId: '   ', method: 'GET', route: '/api/x' }).skippedReason, 'missing_run_id')
  let replayCalls = 0
  const deniedPostReplay = evaluateMustBeNonPublicStage({
    spec: authzSpec,
    steps: [],
    probe: mintProbe,
    replayBudget: activeLedger,
    runId: 'run-dispose-1',
    environmentMode: 'prod_readonly',
    replayProbe: () => { replayCalls += 1; return null },
  })
  assert.equal(replayCalls, 0, 'prod_readonly must NEVER invoke replayProbe for POST')
  assert.equal(deniedPostReplay.passed, false, 'denied active replayProbe must fail closed by default')
  assert.equal(deniedPostReplay.replaySkipped, true)

  const getProbe: ImpactStep = {
    id: 'get-prb',
    arm: 'probe',
    method: 'GET',
    route: '/api/records/7',
    pathAndQuery: '/api/records/7',
    status: 200,
    actor: { handle: 'member_a', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null },
    json: { id: 7, title: 'Open catalog item' },
  }
  const activeGetRes = evaluateMustBeNonPublicStage({
    spec: authzSpec,
    steps: [getProbe],
    probe: getProbe,
    replayBudget: activeLedger,
    runId: 'run-dispose-1',
    environmentMode: 'prod_readonly',
    replayProbe: () => {
      replayCalls += 1
      return {
        id: 'replayed-anon',
        arm: 'control',
        method: 'GET',
        route: '/api/records/7',
        status: 200,
        actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
        json: { id: 7, title: 'Open catalog item' },
      }
    },
  })
  assert.equal(replayCalls, 1)
  assert.equal(activeGetRes.replayExecuted, true)
  assert.equal(activeGetRes.passed, false)
  assert.equal(activeGetRes.public, true)
  assert.equal(activeLedger.getRunUsage('run-dispose-1'), 1)

  // Per-run disposer cleanly evicts ledger state so no cross-run leak remains
  runAllRunDisposers('run-dispose-1')
  assert.equal(activeLedger.getRunUsage('run-dispose-1'), 0)
})
