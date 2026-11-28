/**
 * R3-15: Truthful 'No issue found' — single authoritative `RECORD_COVERAGE_CONTRACT`
 * across tool schema, store, and worker brief, plus route-safe coverage status precedence.
 *
 * Class-level guards:
 *   1. Two-route protection: an open `needs_follow_up` gap on route B is NEVER overwritten
 *      by `no_issue_found` or `ruled_out` on route A (nor evicted when > 6 routes exist).
 *   2. Same-route resolution: when route B itself is later closed with valid run-owned
 *      exchange evidence, its own `needs_follow_up` clears and the category advances cleanly
 *      (while partial resolution of one of two open-gap routes still preserves `needs_follow_up`).
 *   3. Schema-store-prompt contract parity across all 5 `CoverageClosureStatus` values:
 *      zero `COVERAGE_EVIDENCE_REQUIRED` rejections for compliant calls; consistent rejection
 *      for missing required fields (including unverified `/repos file:line` prose without an
 *      exchangeId) at BOTH tool and store boundaries.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'

import { buildWorkerTools } from '../src/server/agent-session.ts'
import {
  ASSIGNMENT_BRIEF_MAX_BYTES,
  ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
  buildAssignmentBriefPacket,
  renderSettlementSpecDirective,
} from '../src/server/assignment-brief.ts'
import {
  RECORD_COVERAGE_CONTRACT,
  buildRecordCoverageBriefGuidance,
  coverageStatusRank,
  extractCoverageEvidenceMetadata,
} from '../src/server/coverage-category.ts'
import { recordReportedFindingCoverage } from '../src/server/exec-exchange.ts'
import { coverageClosureStatuses, type CoverageClosureStatus } from '../src/domain.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const ORIGIN = 'https://r3-15-truth.example.invalid'

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
    pathAndQuery: input.pathAndQuery ?? '/api/items',
    status: input.status ?? 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: {},
    body: '{"ok":true}',
    durationMs: 10,
  })
}

function seedConfirmedFinding(
  storage: ReturnType<typeof makeStore>['storage'],
  input: {
    run: ReturnType<ReturnType<typeof makeStore>['storage']['run']>
    worker: ReturnType<ReturnType<typeof makeStore>['storage']['makeWorker']>
    assetId: string
    origin: string
    category: string
    exchangeId: string
  },
): string {
  const id = randomUUID()
  const specRow = storage.createReplaySpec(input.run, input.worker, id, {
    version: 1,
    origin: input.origin,
    title: `Confirmed ${input.category}`,
    category: input.category,
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Differential verification confirmed',
    impact: 'Unauthorized data access',
    remediation: 'Enforce authorization check',
    recheckInstructions: 'Replay differential check',
    kind: 'http_chain',
    spaCatchallControl: false,
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "diff", expected: "bound" }',
    steps: [
      { id: 'ctrl', role: 'control', description: 'Control', request: { origin: input.origin, method: 'GET', pathAndQuery: '/api/secret', followRedirects: false } },
      { id: 'prb', role: 'probe', description: 'Probe', request: { origin: input.origin, method: 'GET', pathAndQuery: '/api/secret', followRedirects: false } },
    ],
  }, [input.origin], {
    verifiedInline: true,
    lastVerificationDiff: {
      verdict: 'confirmed',
      controlPassed: true,
      assertionSummary: { observed: 'diff', expected: 'bound', reason: 'Confirmed' },
      stepStatuses: [],
      retriesRemaining: 0,
    },
  })
  const artifact = storage.addArtifact(
    input.run,
    input.worker,
    'replay',
    `Verified · ${input.category}`,
    JSON.stringify({
      replaySpecId: specRow.id,
      specSha256: specRow.specSha256,
      kind: 'http_chain',
      verdict: 'confirmed',
      verificationTier: 'runtime_confirmed',
      outcome: { controlPassed: true, confirmed: true, reason: 'Confirmed' },
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
      title: `Confirmed ${input.category}`,
      severity: 'high',
      category: input.category,
      cwe: 'CWE-639',
      status: 'confirmed',
      verificationTier: 'runtime_confirmed',
      confidence: 'high',
      reason: 'Confirmed',
      impact: 'Unauthorized access',
      remediation: 'Enforce authz',
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

async function invokeTool(
  tool: ReturnType<typeof buildWorkerTools>[number],
  args: Record<string, unknown>,
) {
  const exec = tool.execute as unknown as (
    params: Record<string, unknown>,
    api: Record<string, unknown>,
    ctx: { abortSignal: AbortSignal },
  ) => Promise<{ isError?: boolean; output: Array<{ type: string; text?: string }> }>
  return exec(args, {}, { abortSignal: AbortSignal.timeout(5_000) })
}

// ============================================================================
// 1. Two-route gap protection (category NEVER says 'no_issue_found' while route B is open)
// ============================================================================

test('R3-15.1: two-route protection — closing route A with no_issue_found/ruled_out never hides open needs_follow_up on route B', async t => {
  assert.ok(coverageStatusRank('reported') > coverageStatusRank('needs_follow_up'))
  assert.ok(coverageStatusRank('needs_follow_up') > coverageStatusRank('no_issue_found'))
  assert.ok(coverageStatusRank('needs_follow_up') > coverageStatusRank('ruled_out'))

  const { storage } = makeStore(t, 'kovo-r3-15-two-route-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Two-route worker', 'Probe routes', { sourceOrigins: [ORIGIN] })

  // Route B opens a needs_follow_up proof gap.
  const gapEntry = storage.upsertCoverageEntry(run, worker.id, {
    origin: ORIGIN,
    category: 'broken-access-control',
    status: 'needs_follow_up',
    summary: 'Missing second tenant persona on orders endpoint',
    proofGapReason: 'no_authenticated_persona: need cross-tenant session on GET /api/orders/:id',
    route: 'GET /api/orders/:id',
  })
  assert.equal(gapEntry.status, 'needs_follow_up')
  assert.equal(extractCoverageEvidenceMetadata(gapEntry).routeStatuses['GET /api/orders/:id'], 'needs_follow_up')

  // Route A is probed and closed cleanly with no_issue_found + valid run-owned exchangeId.
  const exRouteA = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'GET', pathAndQuery: '/api/catalog' })
  const afterRouteA = storage.upsertCoverageEntry(run, worker.id, {
    origin: ORIGIN,
    category: 'broken-access-control',
    status: 'no_issue_found',
    summary: 'Public catalog route verified read-only',
    route: 'GET /api/catalog',
    exchangeIds: [exRouteA.id],
  })
  assert.equal(
    afterRouteA.status,
    'needs_follow_up',
    'category must NEVER show no_issue_found while route B remains needs_follow_up',
  )
  assert.match(afterRouteA.proofGapReason ?? '', /no_authenticated_persona/, 'open proofGapReason on route B must be preserved')
  const metaA = extractCoverageEvidenceMetadata(afterRouteA)
  assert.equal(metaA.routeStatuses['GET /api/orders/:id'], 'needs_follow_up')
  assert.equal(metaA.routeStatuses['GET /api/catalog'], 'no_issue_found')
  assert.ok(metaA.exchangeIds.includes(exRouteA.id))

  // Route C closed with ruled_out STILL cannot overwrite route B's open gap.
  const exRouteC = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'POST', pathAndQuery: '/api/notes' })
  const afterRouteC = storage.upsertCoverageEntry(run, worker.id, {
    origin: ORIGIN,
    category: 'broken-access-control',
    status: 'ruled_out',
    summary: 'Owner check verified on notes route',
    enforcingControl: `Denied cross-tenant POST in ${exRouteC.id}`,
    route: 'POST /api/notes',
    exchangeIds: [exRouteC.id],
  })
  assert.equal(afterRouteC.status, 'needs_follow_up')
  assert.equal(extractCoverageEvidenceMetadata(afterRouteC).routeStatuses['POST /api/notes'], 'ruled_out')

  // Even 7 additional no_issue_found routes (> 6 route trailer cap) must NEVER evict route B's open gap!
  let latest = afterRouteC
  for (let i = 1; i <= 7; i += 1) {
    const ex = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'GET', pathAndQuery: `/api/extra/${i}` })
    latest = storage.upsertCoverageEntry(run, worker.id, {
      origin: ORIGIN,
      category: 'broken-access-control',
      status: 'no_issue_found',
      summary: `Extra route ${i} clean`,
      route: `GET /api/extra/${i}`,
      exchangeIds: [ex.id],
    })
  }
  assert.equal(latest.status, 'needs_follow_up', 'open gap must survive >6 route closures without eviction')
  assert.equal(extractCoverageEvidenceMetadata(latest).routeStatuses['GET /api/orders/:id'], 'needs_follow_up')

  // Reverse order on another category: route A clean first, then route B opens needs_follow_up -> upgrades to needs_follow_up.
  const exInjA = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'GET', pathAndQuery: '/api/search' })
  const injA = storage.upsertCoverageEntry(run, worker.id, {
    origin: ORIGIN,
    category: 'injection-input',
    status: 'no_issue_found',
    summary: 'Search query parameterized',
    route: 'GET /api/search',
    exchangeIds: [exInjA.id],
  })
  assert.equal(injA.status, 'no_issue_found')

  const injB = storage.upsertCoverageEntry(run, worker.id, {
    origin: ORIGIN,
    category: 'injection-input',
    status: 'needs_follow_up',
    summary: 'Export filter requires async job setup',
    proofGapReason: 'no_spec_shape: async filter pipeline not probed',
    route: 'POST /api/export',
  })
  assert.equal(injB.status, 'needs_follow_up')
  const injMeta = extractCoverageEvidenceMetadata(injB)
  assert.equal(injMeta.routeStatuses['GET /api/search'], 'no_issue_found')
  assert.equal(injMeta.routeStatuses['POST /api/export'], 'needs_follow_up')
})

// ============================================================================
// 2. Same-route resolution (clears its own gap without breaking multi-gap or reported precedence)
// ============================================================================

test('R3-15.2: same-route resolution — closing route B itself clears its needs_follow_up cleanly; reported stays strictly highest', async t => {
  const { storage } = makeStore(t, 'kovo-r3-15-same-route-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Resolution worker', 'Resolve gaps', { sourceOrigins: [ORIGIN] })

  // Two routes (B and C) open needs_follow_up; route A is clean.
  storage.upsertCoverageEntry(run, worker.id, {
    origin: ORIGIN,
    category: 'auth-identity',
    status: 'needs_follow_up',
    summary: 'Token refresh route blocked on second session',
    proofGapReason: 'no_authenticated_persona: refresh route pending',
    route: 'POST /api/auth/refresh',
  })
  const exA = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'GET', pathAndQuery: '/api/auth/me' })
  storage.upsertCoverageEntry(run, worker.id, {
    origin: ORIGIN,
    category: 'auth-identity',
    status: 'no_issue_found',
    summary: 'Profile endpoint requires valid token',
    route: 'GET /api/auth/me',
    exchangeIds: [exA.id],
  })
  storage.upsertCoverageEntry(run, worker.id, {
    origin: ORIGIN,
    category: 'auth-identity',
    status: 'needs_follow_up',
    summary: 'Password reset route needs baseline',
    proofGapReason: 'baseline_empty: reset route pending',
    route: 'POST /api/auth/reset',
  })

  // Closing ONLY route B (`POST /api/auth/refresh`) clears route B, but route C (`POST /api/auth/reset`) is STILL open!
  const exB = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'POST', pathAndQuery: '/api/auth/refresh' })
  const partialClose = storage.upsertCoverageEntry(run, worker.id, {
    origin: ORIGIN,
    category: 'auth-identity',
    status: 'no_issue_found',
    summary: 'Refresh token rotation verified',
    route: 'POST /api/auth/refresh',
    exchangeIds: [exB.id],
  })
  assert.equal(partialClose.status, 'needs_follow_up', 'closing route B must not hide remaining open gap on route C')
  const partialMeta = extractCoverageEvidenceMetadata(partialClose)
  assert.equal(partialMeta.routeStatuses['POST /api/auth/refresh'], 'no_issue_found')
  assert.equal(partialMeta.routeStatuses['POST /api/auth/reset'], 'needs_follow_up')

  // Now closing route C itself (`POST /api/auth/reset`) clears the last open gap -> category cleanly advances to ruled_out!
  const exC = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'POST', pathAndQuery: '/api/auth/reset' })
  const fullClose = storage.upsertCoverageEntry(run, worker.id, {
    origin: ORIGIN,
    category: 'auth-identity',
    status: 'ruled_out',
    summary: 'Reset token single-use binding verified',
    enforcingControl: `Single-use token check verified in ${exC.id}`,
    route: 'POST /api/auth/reset',
    exchangeIds: [exC.id],
  })
  assert.equal(fullClose.status, 'ruled_out', 'closing the final open route must allow category to advance cleanly')
  assert.equal(fullClose.proofGapReason, null, 'cleared gap should not leave stale proofGapReason')
  const fullMeta = extractCoverageEvidenceMetadata(fullClose)
  assert.equal(fullMeta.routeStatuses['POST /api/auth/refresh'], 'no_issue_found')
  assert.equal(fullMeta.routeStatuses['POST /api/auth/reset'], 'ruled_out')
  assert.equal(fullMeta.routeStatuses['GET /api/auth/me'], 'no_issue_found')

  // Active confirmed finding ('reported') MUST stay strictly higher than 'needs_follow_up'!
  const exFinding = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'GET', pathAndQuery: '/api/secret' })
  const findingId = seedConfirmedFinding(storage, {
    run, worker, assetId: asset.id, origin: ORIGIN, category: 'bola', exchangeId: exFinding.id,
  })
  recordReportedFindingCoverage(
    storage, run, worker.id, ORIGIN, 'bola', 'Confirmed BOLA', findingId, () => true,
    { route: 'GET /api/secret', exchangeIds: [exFinding.id] },
  )
  const gapOnReported = storage.upsertCoverageEntry(run, worker.id, {
    origin: ORIGIN,
    category: 'broken-access-control',
    status: 'needs_follow_up',
    summary: 'Secondary route needs follow up',
    proofGapReason: 'no_spec_shape: secondary route',
    route: 'POST /api/secret/bulk',
  })
  assert.equal(gapOnReported.status, 'reported', 'reported must stay strictly higher than needs_follow_up')
  assert.equal(gapOnReported.linkedFindingId, findingId)
})

// ============================================================================
// 3. Schema-store-prompt contract parity across all 5 statuses
// ============================================================================

test('R3-15.3: schema-store-prompt contract parity — zero COVERAGE_EVIDENCE_REQUIRED rejections for compliant calls across all 5 statuses', async t => {
  const { storage } = makeStore(t, 'kovo-r3-15-parity-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Parity worker', 'Verify contract parity', { sourceOrigins: [ORIGIN] })

  const exRuledOut = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'POST', pathAndQuery: '/api/transfer' })
  const exNoIssue = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'GET', pathAndQuery: '/api/health' })
  const exReported = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, method: 'GET', pathAndQuery: '/api/secret' })
  const findingId = seedConfirmedFinding(storage, {
    run, worker, assetId: asset.id, origin: ORIGIN, category: 'sqli', exchangeId: exReported.id,
  })

  let coverageEvidenceRequiredRejections = 0
  const tools = buildWorkerTools(
    {
      record_coverage: async args => {
        try {
          return storage.upsertCoverageEntry(run, worker.id, {
            origin: args.origin,
            category: args.category,
            status: args.status,
            summary: args.summary,
            enforcingControl: args.enforcingControl,
            proofGapReason: args.proofGapReason,
            linkedFindingId: args.linkedFindingId,
            route: args.route,
            branchKey: args.branchKey,
            exchangeIds: args.exchangeIds,
          })
        } catch (err) {
          if (err instanceof Error && err.message.includes('COVERAGE_EVIDENCE_REQUIRED')) {
            coverageEvidenceRequiredRejections += 1
          }
          throw err
        }
      },
    },
    v => v,
    AbortSignal.timeout(5_000),
    16_384,
    () => {},
  )
  const recordCoverageTool = tools.find(tool => tool.name === 'record_coverage')!
  assert.ok(recordCoverageTool)

  // Compliant payloads built strictly from RECORD_COVERAGE_CONTRACT for all 5 statuses.
  const compliantByStatus: Record<CoverageClosureStatus, Record<string, unknown>> = {
    reported: {
      origin: ORIGIN,
      category: 'injection-input',
      status: 'reported',
      summary: 'Confirmed SQL injection via differential verification',
      linkedFindingId: findingId,
      route: 'GET /api/secret',
      exchangeIds: [exReported.id],
    },
    ruled_out: {
      origin: ORIGIN,
      category: 'business-logic-race',
      status: 'ruled_out',
      summary: 'Idempotency key guard verified against replay',
      enforcingControl: `Idempotency guard enforced 409 Conflict (${exRuledOut.id})`,
      route: 'POST /api/transfer',
      exchangeIds: [exRuledOut.id],
    },
    no_issue_found: {
      origin: ORIGIN,
      category: 'misconfig-exposure',
      status: 'no_issue_found',
      summary: 'Health endpoint returns status only with no internal leaks',
      route: 'GET /api/health',
      exchangeIds: [exNoIssue.id],
    },
    needs_follow_up: {
      origin: ORIGIN,
      category: 'broken-access-control',
      status: 'needs_follow_up',
      summary: 'Admin bulk endpoint requires elevated session to verify',
      proofGapReason: 'no_authenticated_persona: admin persona unavailable',
      route: 'POST /api/admin/bulk',
    },
    not_applicable: {
      origin: ORIGIN,
      category: 'llm-ai-security',
      status: 'not_applicable',
      summary: 'Target exposes no LLM or AI prompt surface',
    },
  }

  for (const status of coverageClosureStatuses) {
    const payload = compliantByStatus[status]
    // Verify payload supplies every field declared in RECORD_COVERAGE_CONTRACT[status].requiredFields.
    for (const reqField of RECORD_COVERAGE_CONTRACT[status].requiredFields) {
      assert.ok(payload[reqField], `test payload for "${status}" must supply required field "${reqField}"`)
    }
    const res = await invokeTool(recordCoverageTool, payload)
    assert.notEqual(res.isError, true, `compliant record_coverage call for status="${status}" must succeed: ${res.output[0]?.text ?? ''}`)
  }
  assert.equal(coverageEvidenceRequiredRejections, 0, 'zero COVERAGE_EVIDENCE_REQUIRED rejections for compliant calls across all 5 statuses')

  // Non-compliant white-box prose-only ruled_out (file:line without exchangeId) must fail consistently at BOTH tool AND store!
  const proseOnlyRuledOut = {
    origin: ORIGIN,
    category: 'crypto-tls-transport' as const,
    status: 'ruled_out' as const,
    summary: 'Saw constant-time compare in source',
    enforcingControl: '/repos/app/src/crypto.ts:42',
  }
  const toolReject = await invokeTool(recordCoverageTool, proseOnlyRuledOut)
  assert.equal(toolReject.isError, true, 'tool boundary must fail fast on prose-only ruled_out missing exchangeIds')
  assert.match(toolReject.output[0]?.text ?? '', /exchangeId/i)
  assert.throws(
    () => storage.upsertCoverageEntry(run, worker.id, proseOnlyRuledOut),
    /exchangeId/i,
    'store boundary must identically reject prose-only ruled_out missing exchangeIds',
  )

  // Non-compliant no_issue_found missing exchangeIds must fail consistently at BOTH tool AND store!
  const noExNoIssue = {
    origin: ORIGIN,
    category: 'crypto-tls-transport' as const,
    status: 'no_issue_found' as const,
    summary: 'No TLS issues observed',
  }
  const toolRejectNoIssue = await invokeTool(recordCoverageTool, noExNoIssue)
  assert.equal(toolRejectNoIssue.isError, true, 'tool boundary must fail fast on no_issue_found missing exchangeIds')
  assert.throws(
    () => storage.upsertCoverageEntry(run, worker.id, noExNoIssue),
    /exchangeId/i,
  )

  // Worker briefs & settlement directive stay inside strict byte caps while surfacing RECORD_COVERAGE_CONTRACT guidance.
  const guidance = buildRecordCoverageBriefGuidance()
  const singlePacket = buildAssignmentBriefPacket({
    missionKind: 'class_scan',
    origin: ORIGIN,
    routes: [{ method: 'GET', path: '/api/orders/:id', riskScore: 80 }],
  })
  assert.ok(singlePacket.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES, `single-hop brief ${singlePacket.bytes} B > ${ASSIGNMENT_BRIEF_MAX_BYTES} B`)
  assert.ok(singlePacket.text.includes(guidance))

  const chainPacket = buildAssignmentBriefPacket({
    missionKind: 'multihop_chain',
    origin: ORIGIN,
    routes: [{ method: 'POST', path: '/api/transfer', riskScore: 95 }],
  })
  assert.ok(chainPacket.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE, `chain brief ${chainPacket.bytes} B > 4 KB`)
  const directive = renderSettlementSpecDirective(
    { method: 'GET', path: '/api/orders/:id', origin: ORIGIN },
    'kovo_verify({ script })',
    ['no_spec_shape'],
  )
  assert.ok(directive.includes(guidance))
})
