/**
 * R2-14: Truthful 'No issue found' — route-scoped, evidence-backed, monotone coverage,
 * shared class -> OWASP projection, evidence-backed planner closure, observational
 * `coverage.precondition_unmet` events, and typed `(method, route, class)` gap reporting.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'
import { eq } from 'drizzle-orm'

import {
  categoryToOwaspCoverageCategory,
  coverageStatusRank,
  extractCoverageEvidenceMetadata,
} from '../src/server/coverage-category.ts'
import { buildCoverageGapReport, formatCoverageGapMarkdown } from '../src/server/coverage-gaps.ts'
import { recordReportedFindingCoverage } from '../src/server/exec-exchange.ts'
import type { ExecFloorLane } from '../src/server/exec-floor-lane.ts'
import type { ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import { Execution } from '../src/server/execution.ts'
import { coverageEntries, endpoints, events, findings } from '../src/server/schema.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const ORIGIN = 'https://r2-14-app.example.invalid'
const OTHER_ORIGIN = 'https://r2-14-other.example.invalid'

function stubBackend(): WorkerBackend {
  return {
    async run() { return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} } },
    async verifyStaticAst(_aid, req) {
      return {
        verified: false, engine: req.engine, repo: req.repo, file: req.file,
        startLine: req.startLine, endLine: req.endLine, matchedLines: [],
        codeExcerpt: '', matchCount: 0, durationMs: 1,
      }
    },
    async openSession(): Promise<WorkerSession> {
      return {
        stage: async name => `/evidence/${name}`,
        exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
        analyze: async () => ({ ok: true }),
        sast: async req => ({ repo: req.repo, enginesRun: [], engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
        runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }),
        verifyStaticAst: async req => ({
          verified: false, engine: req.engine, repo: req.repo, file: req.file,
          startLine: req.startLine, endLine: req.endLine, matchedLines: [],
          codeExcerpt: '', matchCount: 0, durationMs: 1,
        }),
        close: async () => undefined,
      }
    },
  }
}

function internals(engine: Execution) {
  return engine as unknown as {
    reconPlanner: ExecReconPlanner
    floorLane: ExecFloorLane
  }
}

function seedExchange(
  storage: ReturnType<typeof makeStore>['storage'],
  input: { runId: string; assignmentId: string; origin: string; method?: string; pathAndQuery?: string; status?: number },
) {
  return storage.recordExchange({
    runId: input.runId,
    assignmentId: input.assignmentId,
    scopeRevision: 1,
    origin: input.origin,
    finalOrigin: input.origin,
    redirectOrigins: [input.origin],
    method: input.method ?? 'GET',
    pathAndQuery: input.pathAndQuery ?? '/api/items/1',
    status: input.status ?? 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: {},
    body: '{"ok":true}',
    durationMs: 10,
  })
}

function seedFinding(
  storage: ReturnType<typeof makeStore>['storage'],
  input: {
    id?: string
    run: ReturnType<ReturnType<typeof makeStore>['storage']['run']>
    worker: ReturnType<ReturnType<typeof makeStore>['storage']['makeWorker']>
    assetId: string
    origin: string
    category: string
    route: string
    exchangeId: string
  },
) {
  const id = input.id ?? randomUUID()
  const [method = 'GET', pathAndQuery = '/api/test'] = input.route.split(' ')
  const specRow = storage.createReplaySpec(input.run, input.worker, id, {
    version: 1,
    origin: input.origin,
    title: `Floor confirmed ${input.category}`,
    category: input.category,
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Differential verification confirmed',
    impact: 'Unauthorized access or impact',
    remediation: 'Enforce validation/authorization',
    recheckInstructions: `Replay ${input.route}`,
    kind: 'http_chain',
    spaCatchallControl: false,
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "diff", expected: "bound" }',
    steps: [
      { id: 'ctrl', role: 'control', description: 'Control', request: { origin: input.origin, method: method as 'GET' | 'POST', pathAndQuery, followRedirects: false } },
      { id: 'prb', role: 'probe', description: 'Probe', request: { origin: input.origin, method: method as 'GET' | 'POST', pathAndQuery, followRedirects: false } },
    ],
  }, [input.origin], {
    verifiedInline: true,
    lastVerificationDiff: {
      verdict: 'confirmed',
      controlPassed: true,
      assertionSummary: { observed: 'diff', expected: 'bound', reason: 'Differential verification confirmed' },
      stepStatuses: [],
      retriesRemaining: 0,
    },
  })
  const artifact = storage.addArtifact(
    input.run,
    input.worker,
    'replay',
    `Deterministic verified · ${input.category}`,
    JSON.stringify({
      replaySpecId: specRow.id,
      specSha256: specRow.specSha256,
      kind: 'http_chain',
      verdict: 'confirmed',
      verificationTier: 'runtime_confirmed',
      outcome: { controlPassed: true, confirmed: true, reason: 'Differential verification confirmed' },
      exchangeIds: [input.exchangeId],
    }),
    `replay:${specRow.id}`,
  )
  const saved = storage.upsertChainFinding(
    input.run,
    input.assetId,
    {
      id,
      origin: input.origin,
      title: `Floor confirmed ${input.category}`,
      severity: 'high',
      category: input.category,
      cwe: 'CWE-639',
      status: 'confirmed',
      verificationTier: 'runtime_confirmed',
      confidence: 'high',
      reason: 'Differential verification confirmed',
      impact: 'Unauthorized access or impact',
      remediation: 'Enforce validation/authorization',
      verification: 'Replay confirmed',
      findingKind: 'multi_step_chain',
      replaySpecId: specRow.id,
      evidenceIds: [artifact.id],
      exchangeIds: [input.exchangeId],
      scopeRevision: input.run.scopeRevision,
    },
    specRow.id,
    [input.origin],
    { provenance: 'floor', verificationClass: 'runtime_confirmed' },
  )
  return saved.id
}

// ============================================================================
// 1. Shared class -> OWASP map & monotone floor coverage protection
// ============================================================================

test('R2-14.1: categoryToOwaspCoverageCategory maps all floor/agentic classes and floor confirmations mark cells that cannot be overwritten by no_issue_found', async t => {
  const expectedMappings: Array<[string, string]> = [
    ['xxe', 'injection-input'],
    ['sqli', 'injection-input'],
    ['cmdi', 'injection-input'],
    ['command_injection', 'injection-input'],
    ['ssti', 'injection-input'],
    ['nosqli', 'injection-input'],
    ['cache', 'injection-input'],
    ['ssrf', 'ssrf-redirects'],
    ['open-redirect', 'ssrf-redirects'],
    ['xss', 'cors-client-side'],
    ['dom_xss', 'cors-client-side'],
    ['csrf', 'cors-client-side'],
    ['cors', 'cors-client-side'],
    ['path-traversal', 'broken-access-control'],
    ['bola', 'broken-access-control'],
    ['bfla', 'broken-access-control'],
    ['idor', 'broken-access-control'],
    ['cross_tenant_write', 'broken-access-control'],
    ['graphql', 'broken-access-control'],
    ['mass-assignment', 'broken-access-control'],
    ['jwt', 'auth-identity'],
    ['webhook', 'auth-identity'],
    ['race', 'business-logic-race'],
    ['race_double_spend', 'business-logic-race'],
    ['price_tampering', 'business-logic-race'],
    ['information-disclosure', 'misconfig-exposure'],
    ['upload', 'upload-storage'],
    ['dns-takeover', 'dns-takeover-infra'],
    ['prompt-injection', 'llm-ai-security'],
  ]
  for (const [raw, expected] of expectedMappings) {
    assert.equal(categoryToOwaspCoverageCategory(raw), expected, `expected ${raw} -> ${expected}`)
  }
  assert.ok(coverageStatusRank('reported') > coverageStatusRank('no_issue_found'))
  assert.ok(coverageStatusRank('no_issue_found') > coverageStatusRank('unprobed'))

  const { storage } = makeStore(t, 'kovo-r2-14-floor-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Floor worker', 'Floor pass', { sourceOrigins: [ORIGIN] })

  const floorCases = [
    { category: 'xxe', owasp: 'injection-input', route: 'POST /api/xml' },
    { category: 'ssrf', owasp: 'ssrf-redirects', route: 'POST /api/fetch' },
    { category: 'path-traversal', owasp: 'broken-access-control', route: 'GET /api/files' },
    { category: 'jwt', owasp: 'auth-identity', route: 'GET /api/profile' },
    { category: 'race', owasp: 'business-logic-race', route: 'POST /api/redeem' },
  ] as const

  const linkedIds = new Map<string, string>()
  for (const fc of floorCases) {
    const ex = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: fc.route.split(' ')[0], pathAndQuery: fc.route.split(' ')[1] })
    const findingId = seedFinding(storage, { run, worker, assetId: asset.id, origin: ORIGIN, category: fc.category, route: fc.route, exchangeId: ex.id })
    linkedIds.set(fc.owasp, findingId)

    // Verify Finding.category stays untouched as the concrete floor grader key.
    const storedFinding = storage.db.select().from(findings).where(eq(findings.id, findingId)).get()!
    assert.equal(storedFinding.finding.category, fc.category)

    recordReportedFindingCoverage(
      storage,
      run,
      worker.id,
      ORIGIN,
      fc.category,
      `Deterministic verified: ${fc.category}`,
      findingId,
      () => true,
      { route: fc.route, exchangeIds: [ex.id] },
    )

    // Attempt to overwrite the cell with no_issue_found (even WITH a valid run-owned origin-matched exchange!).
    const negEx = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'GET', pathAndQuery: '/api/other' })
    const afterAttempt = storage.upsertCoverageEntry(run, worker.id, {
      origin: ORIGIN,
      category: fc.owasp,
      status: 'no_issue_found',
      summary: 'Negative probe on another route',
      route: 'GET /api/other',
      exchangeIds: [negEx.id],
    })
    assert.equal(afterAttempt.status, 'reported', `cell ${fc.owasp} must NEVER demote from reported to no_issue_found while finding is active`)
    assert.equal(afterAttempt.linkedFindingId, findingId)
    const meta = extractCoverageEvidenceMetadata(afterAttempt)
    assert.ok(meta.routes.includes(fc.route), `expected route ${fc.route} preserved`)
    assert.ok(meta.exchangeIds.includes(ex.id), 'expected floor exchangeId preserved')
    assert.ok(meta.exchangeIds.includes(negEx.id), 'expected merged negative probe exchangeId preserved')
  }

  // Demotion IS allowed ONLY once the linked confirmed finding is dismissed or superseded!
  const jwtFindingId = linkedIds.get('auth-identity')!
  storage.client.prepare(`UPDATE findings SET status = 'dismissed', finding = json_set(finding, '$.status', 'dismissed') WHERE id = ?`).run(jwtFindingId)
  const cleanEx = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'GET', pathAndQuery: '/api/profile' })
  const demoted = storage.upsertCoverageEntry(run, worker.id, {
    origin: ORIGIN,
    category: 'auth-identity',
    status: 'ruled_out',
    summary: 'JWT signature verification enforced',
    enforcingControl: `Verified negative control ${cleanEx.id}`,
    route: 'GET /api/profile',
    branchKey: 'branch:jwt-check',
    exchangeIds: [cleanEx.id],
  })
  assert.equal(demoted.status, 'ruled_out', 'demotion must succeed once linked finding is dismissed')
  assert.equal(demoted.linkedFindingId, null)
  const demotedMeta = extractCoverageEvidenceMetadata(demoted)
  assert.equal(demotedMeta.branchKey, 'branch:jwt-check')
  assert.ok(demotedMeta.exchangeIds.includes(cleanEx.id))

  // Also test superseded linked finding allows demotion.
  const raceFindingId = linkedIds.get('business-logic-race')!
  storage.client.prepare(`UPDATE findings SET superseded_by_finding_id = 'superseded-ref' WHERE id = ?`).run(raceFindingId)
  const raceEx = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'POST', pathAndQuery: '/api/redeem' })
  const demotedRace = storage.upsertCoverageEntry(run, worker.id, {
    origin: ORIGIN,
    category: 'business-logic-race',
    status: 'no_issue_found',
    summary: 'Atomic ledger lock verified',
    route: 'POST /api/redeem',
    exchangeIds: [raceEx.id],
  })
  assert.equal(demotedRace.status, 'no_issue_found', 'demotion must succeed once linked finding is superseded')
})

// ============================================================================
// 2. Evidence-backed negative coverage & fail-closed exchange verification
// ============================================================================

test('R2-14.2: no_issue_found/ruled_out require run-owned origin-matched exchangeIds, reject cross-run/wrong-origin spoofs, and gate planner closure', async t => {
  const { storage } = makeStore(t, 'kovo-r2-14-evidence-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN, OTHER_ORIGIN], tier: 2 })
  const { runId: otherRunId, run: otherRun } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })

  const asset = run.candidates.find(c => c.origin === ORIGIN && run.approved.includes(c.id))!
  const otherAsset = otherRun.candidates.find(c => c.origin === ORIGIN && otherRun.approved.includes(c.id))!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Worker A', 'Probe routes', { sourceOrigins: [ORIGIN] })
  const otherRunWorker = storage.makeWorker(otherRun, 'investigation', otherAsset, 'Other Run Worker', 'Probe', { sourceOrigins: [ORIGIN] })

  const crossRunEx = seedExchange(storage, { runId: otherRunId, assignmentId: otherRunWorker.id, origin: ORIGIN, method: 'GET', pathAndQuery: '/api/orders' })
  const wrongOriginEx = seedExchange(storage, { runId, assignmentId: worker.id, origin: OTHER_ORIGIN, method: 'GET', pathAndQuery: '/api/orders' })
  const validEx = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'GET', pathAndQuery: '/api/orders' })

  // (a) Missing exchangeIds -> rejected fail-closed for both no_issue_found and ruled_out.
  assert.throws(
    () => storage.upsertCoverageEntry(run, worker.id, {
      origin: ORIGIN,
      category: 'injection-input',
      status: 'no_issue_found',
      summary: 'Claimed clean without evidence',
      route: 'GET /api/orders',
    }),
    /run-owned, origin-matched exchangeId/i,
  )
  assert.throws(
    () => storage.upsertCoverageEntry(run, worker.id, {
      origin: ORIGIN,
      category: 'injection-input',
      status: 'ruled_out',
      summary: 'Claimed ruled out without evidence',
      enforcingControl: 'src/orders.ts:42',
    }),
    /run-owned, origin-matched exchangeId/i,
  )

  // (b) Fabricated / non-existent exchangeId -> rejected fail-closed.
  assert.throws(
    () => storage.upsertCoverageEntry(run, worker.id, {
      origin: ORIGIN,
      category: 'injection-input',
      status: 'no_issue_found',
      summary: 'Fabricated exchange',
      exchangeIds: ['ex-does-not-exist'],
    }),
    /rejected/i,
  )

  // (c) Cross-run exchangeId -> rejected fail-closed.
  assert.throws(
    () => storage.upsertCoverageEntry(run, worker.id, {
      origin: ORIGIN,
      category: 'injection-input',
      status: 'ruled_out',
      summary: 'Cross-run spoof',
      enforcingControl: 'Cross-run control',
      exchangeIds: [crossRunEx.id],
    }),
    /rejected/i,
  )

  // (d) Wrong-origin exchangeId (same run, different origin!) -> rejected fail-closed.
  assert.throws(
    () => storage.upsertCoverageEntry(run, worker.id, {
      origin: ORIGIN,
      category: 'injection-input',
      status: 'no_issue_found',
      summary: 'Wrong-origin spoof',
      exchangeIds: [wrongOriginEx.id],
    }),
    /rejected/i,
  )

  // (e) Planner closure: evidence-free or spoofed rows MUST NOT close assignments; verified rows MUST close!
  const engine = new Execution(storage, { backend: stubBackend() })
  t.after(() => engine.stop())
  const { reconPlanner } = internals(engine)

  // Seed two Tier-A leads so passOneCoverageFor tracks both endpoints.
  storage.addFact(run, worker, {
    kind: 'note', origin: ORIGIN, summary: 'Lead orders',
    data: {
      producer: 'host_planner', source: 'program_graph', kind: 'det_lead',
      endpoint: '/api/orders', method: 'GET', probeClass: 'sqli',
      codeSlice: { hops: [{ file: 'orders.ts', line: 10 }] },
    },
    sourceOrigins: [ORIGIN],
  })
  storage.addFact(run, worker, {
    kind: 'note', origin: ORIGIN, summary: 'Lead users',
    data: {
      producer: 'host_planner', source: 'program_graph', kind: 'det_lead',
      endpoint: '/api/users', method: 'GET', probeClass: 'bola',
      codeSlice: { hops: [{ file: 'users.ts', line: 20 }] },
    },
    sourceOrigins: [ORIGIN],
  })

  const step1 = storage.addChainStep(run, { title: 'Step orders', hypothesis: 'Test orders', category: 'injection-input', targetAssetIds: [asset.id], sourceOrigins: [ORIGIN] })
  const w1 = storage.makeWorker(run, 'investigation', asset, step1.title, step1.hypothesis, { stepId: step1.id, sourceOrigins: [ORIGIN] })
  reconPlanner.registerStepTargets(runId, step1.id, [{ origin: ORIGIN, method: 'GET', route: '/api/orders', vulnClass: 'injection-input' }])
  storage.updateChainStep(step1.id, { status: 'complete', assignedWorkerId: w1.id })

  const step2 = storage.addChainStep(run, { title: 'Step users', hypothesis: 'Test users', category: 'broken-access-control', targetAssetIds: [asset.id], sourceOrigins: [ORIGIN] })
  const w2 = storage.makeWorker(run, 'investigation', asset, step2.title, step2.hypothesis, { stepId: step2.id, sourceOrigins: [ORIGIN] })
  reconPlanner.registerStepTargets(runId, step2.id, [{ origin: ORIGIN, method: 'GET', route: '/api/users', vulnClass: 'broken-access-control' }])
  storage.updateChainStep(step2.id, { status: 'complete', assignedWorkerId: w2.id })

  // Legacy / bypassed evidence-free no_issue_found row on w1 AND spoofed cross-run exchange on w2 -> NEITHER closes!
  storage.db.insert(coverageEntries).values({
    id: 'legacy-unverified-1',
    runId,
    scopeRevision: run.scopeRevision,
    goalRevision: run.goalRevision,
    origin: ORIGIN,
    category: 'injection-input',
    status: 'no_issue_found',
    summary: 'Evidence-free no issue found',
    assignmentId: w1.id,
    updatedAt: Date.now(),
  }).run()
  storage.db.insert(coverageEntries).values({
    id: 'spoofed-cross-run-2',
    runId,
    scopeRevision: run.scopeRevision,
    goalRevision: run.goalRevision,
    origin: ORIGIN,
    category: 'broken-access-control',
    status: 'ruled_out',
    summary: `Spoofed cross-run exchange [route=GET /api/users] [exchanges=${crossRunEx.id}]`,
    enforcingControl: 'authz middleware',
    assignmentId: w2.id,
    updatedAt: Date.now(),
  }).run()

  const covBeforeVerified = reconPlanner.passOneCoverageFor(run, storage.listChainSteps(runId))
  assert.deepEqual(
    covBeforeVerified.uncoveredTierAEndpoints,
    ['GET /api/orders', 'GET /api/users'],
    'evidence-free and cross-run spoofed coverage rows must NOT close planner assignments',
  )

  // Now record a valid evidence-backed no_issue_found on w1 using validEx -> ONLY GET /api/orders closes!
  const verifiedEntry = storage.upsertCoverageEntry(run, w1.id, {
    origin: ORIGIN,
    category: 'injection-input',
    status: 'no_issue_found',
    summary: 'Parameterized query verified',
    route: 'GET /api/orders',
    branchKey: 'branch:orders-sqli',
    exchangeIds: [validEx.id],
  })
  assert.equal(verifiedEntry.status, 'no_issue_found')
  const meta = extractCoverageEvidenceMetadata(verifiedEntry)
  assert.equal(meta.route, 'GET /api/orders')
  assert.equal(meta.branchKey, 'branch:orders-sqli')
  assert.deepEqual(meta.exchangeIds, [validEx.id])

  const covAfterVerified = reconPlanner.passOneCoverageFor(run, storage.listChainSteps(runId))
  assert.deepEqual(
    covAfterVerified.uncoveredTierAEndpoints,
    ['GET /api/users'],
    'verified run-owned origin-matched coverage row must close its planner assignment',
  )
})

// ============================================================================
// 3. Observational precondition_unmet + typed route+class coverage-gaps.ts
// ============================================================================

test('R2-14.3: observational coverage.precondition_unmet, capped_out, host_skipped, and route+class uncovered_routes surface in buildCoverageGapReport', async t => {
  const { storage } = makeStore(t, 'kovo-r2-14-gaps-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 0 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Gap worker', 'Observe gaps', { sourceOrigins: [ORIGIN] })

  const engine = new Execution(storage, { backend: stubBackend() })
  t.after(() => engine.stop())
  const { reconPlanner } = internals(engine)

  // (a) Planner Tier-0 guard emits observational coverage.precondition_unmet without changing return value.
  const promoted = reconPlanner.promoteInvariantHypothesesToWave1ChainSteps(run, {
    mode: 'source',
    hypotheses: [{
      id: 'hyp-1',
      kind: 'cross_surface_authz',
      title: 'Cross-surface invariant',
      summary: 'Invariant summary',
      severity: 'high',
      score: 0.9,
      evidence: ['GET /api/orders'],
      preconditions: [],
      endpoints: ['GET /api/orders'],
      codeLocations: [],
    }],
    summary: '1 hypothesis',
  } as never)
  assert.deepEqual(promoted, [])

  const precondEvents = storage.db.select().from(events).where(eq(events.runId, runId)).all()
    .filter(ev => ev.kind === 'coverage.precondition_unmet')
  assert.equal(precondEvents.length, 1)
  assert.equal(precondEvents[0]!.detail.precondition, 'tier')

  // (b) Floor tier-1 / 1-persona guard emits observational coverage.precondition_unmet for BOLA.
  storage.updateRun(runId, { capabilityTier: 1, status: 'running', phase: 'investigation' })
  await internals(engine).floorLane.runDeterministicInvestigation(storage.run(runId))
  const allPrecondEvents = storage.db.select().from(events).where(eq(events.runId, runId)).all()
    .filter(ev => ev.kind === 'coverage.precondition_unmet')
  assert.ok(
    allPrecondEvents.some(ev => ev.detail.vulnClass === 'bola' && ev.detail.precondition === 'tier'),
    'expected floor BOLA precondition_unmet event when tier < 2',
  )

  // (c) Seed capped_out event + per-route unprobed tail fact + host_skipped event + sink-bearing route.
  storage.addFact(run, worker, {
    kind: 'note',
    origin: ORIGIN,
    summary: 'Unprobed floor tail (intent_cap, sqli) on POST /api/search',
    data: {
      subkind: 'deterministic_engine_unprobed_tail',
      source: 'deterministic_engine',
      kind: 'det_lead',
      probeClass: 'sqli',
      intent: 'sqli',
      endpoint: '/api/search',
      method: 'POST',
      cappedOutStage: 'intent_cap',
      reason: 'per-class intent cap reached',
    },
    exchangeIds: [],
    sourceOrigins: [ORIGIN],
  })
  storage.event(runId, 'deterministic_engine.capped_out', 'Capped out sqli and ssrf hypotheses.', {
    origin: ORIGIN,
    stoppedReason: 'budget',
    cappedOut: [
      { cap: 8, stage: 'intent_cap', class: 'sqli', kept: 8, dropped: 3 },
      { cap: 4, stage: 'budget', class: 'ssrf', kept: 2, dropped: 2, method: 'POST', route: '/api/webhooks' },
    ],
  })
  storage.event(runId, 'coverage.host_skipped', 'Host skipped due to edge auth wall', {
    origin: OTHER_ORIGIN,
    reason: 'edge_protected',
    method: 'ANY',
    route: '*',
    vulnClass: 'all',
  })

  // Seed discovered routes:
  // 1. GET /api/orders with sinkKinds=['sqli', 'bola'] and only 1 GET exchange (no testedClasses) -> BOTH classes remain uncovered!
  // 2. POST /api/orders with sinkKinds=[] -> GET /api/orders exchange MUST NOT mark POST /api/orders covered!
  const now = Date.now()
  storage.db.insert(endpoints).values([
    {
      id: randomUUID(),
      runId,
      scopeRevision: 1,
      origin: ORIGIN,
      method: 'GET',
      pathTemplate: '/api/orders',
      source: 'openapi',
      sinkKinds: ['sqli', 'bola'],
      testedClasses: [],
      createdAt: now,
      updatedAt: now,
    },
    {
      id: randomUUID(),
      runId,
      scopeRevision: 1,
      origin: ORIGIN,
      method: 'POST',
      pathTemplate: '/api/orders',
      source: 'openapi',
      sinkKinds: [],
      testedClasses: [],
      createdAt: now,
      updatedAt: now,
    },
  ]).run()
  seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'GET', pathAndQuery: '/api/orders' })

  const report = buildCoverageGapReport(storage, runId)
  assert.ok(report.countsByKind.precondition_unmet >= 2, 'expected precondition_unmet gaps')
  assert.equal(report.countsByKind.capped_out, 2, 'expected 2 route+class capped_out gaps')
  assert.equal(report.countsByKind.host_skipped, 1, 'expected 1 host_skipped gap')
  assert.equal(report.countsByKind.uncovered_routes, 3, 'GET /api/orders must report sqli + bola uncovered AND POST /api/orders must remain uncovered')

  const sqliCapped = report.gaps.find(g => g.kind === 'capped_out' && g.vulnClass === 'sqli')
  assert.ok(sqliCapped)
  assert.equal(sqliCapped.route, 'POST /api/search')
  assert.equal(sqliCapped.method, 'POST')

  const ssrfCapped = report.gaps.find(g => g.kind === 'capped_out' && g.vulnClass === 'ssrf')
  assert.ok(ssrfCapped)
  assert.equal(ssrfCapped.route, 'POST /api/webhooks')
  assert.equal(ssrfCapped.count, 2)

  const uncoveredKeys = report.gaps
    .filter(g => g.kind === 'uncovered_routes')
    .map(g => `${g.route}|${g.vulnClass}`)
    .sort()
  assert.deepEqual(uncoveredKeys, [
    'GET /api/orders|bola',
    'GET /api/orders|sqli',
    'POST /api/orders|all',
  ])

  const md = formatCoverageGapMarkdown(report)
  assert.match(md, /`precondition_unmet`/)
  assert.match(md, /`capped_out`/)
  assert.match(md, /`host_skipped`/)
  assert.match(md, /POST \/api\/search.*\[sqli\]/)
})
