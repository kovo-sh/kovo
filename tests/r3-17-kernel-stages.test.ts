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

  // Strict JSON mode rejects broken JSON body
  const badJson = normalizeRequestCarrier(
    { pathAndQuery: '/api/items', requestBody: '{"broken":', requestHeaders: { 'content-type': 'application/json' } },
    { strictJson: true },
  )
  assert.equal(badJson.malformedJson, true)
  assert.equal(badJson.malformedEscape, true)
  assert.equal(badJson.malformedReason, 'malformed_json_body')

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
      route: '/api/ws/events',
      status: 200,
      actorHandle: 'member_a',
      actorRole: 'member',
      requestHeaders: { authorization: 'Bearer revoked-session-token-123' },
      timestampMs: 1_700_000_020_000,
    },
  })
  assert.equal(cleanTemporal.ok, true, 'v8:temporal_revocation legitimate post-revocation time difference must be preserved')
  assert.equal(cleanTemporal.contractRole, 'denied_revoked')

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
      route: '/api/ws/events',
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
    const { factLog, controlId, probeId, anonId } = buildFactLogForSpec(spec, { anonymousPublic: true })
    const onKernelStageExecuted = (ev: { stage: string; specId: string; ok: boolean }) => {
      if (ev.stage === 'must_be_non_public') {
        executedSpecIds.add(ev.specId)
        if (!ev.ok) rejectedSpecIds.add(ev.specId)
      }
    }
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

  assert.equal(executedSpecIds.size, boundarySpecs.length, 'must_be_non_public must execute for 100% of boundary specs')
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
