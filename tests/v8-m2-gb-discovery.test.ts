/**
 * v8 M2 Grey-Box Discovery, `checkpoint_only` Circuit-Breaker & Multi-Hop Guidance Tests.
 *
 * Pure behavioral regression suite covering:
 *  1. Cross-origin `publicOrigins` + sibling routes + sibling `resourceSamples` rendered in
 *     Grey-Box `AssignmentBrief` (`assignment-brief.ts`, `exec-recon-planner.ts`) and surfaced
 *     in `workerInvestigationPrompt` (`agent-prompts.ts`), strictly within the 4 KB brief cap.
 *  2. `checkpoint_only` treated as a script failure in `summarizeKovoVerifyOutcome` (preserving
 *     `usageHint`, omitting misleading `sealedCapabilities`/`verifiedHops`) AND the per-session
 *     consecutive `checkpoint_only` circuit-breaker in `createCheckpointOnlySessionGuard`.
 *  3. Generic (zero v8 contamination) prompt/brief/playbook guidance enforcing:
 *     - Push to terminal impact (never stop at intermediate invite/token/metadata/role-write hops)
 *     - Attacker/low-priv persona ONLY for discovery & attack hops (no victim/owner/admin shortcuts)
 *     - Dual-tenant base persona class selection (`dual_tenant_abac`, never unmapped `cross_tenant_data_access`).
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { dirname, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  CHECKPOINT_ONLY_CIRCUIT_BREAKER_THRESHOLD,
  createCheckpointOnlySessionGuard,
  summarizeKovoVerifyOutcome,
  workerInvestigationPrompt,
} from '../src/server/agent-prompts.ts'
import {
  ASSIGNMENT_BRIEF_MAX_BYTES,
  ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
  buildAssignmentBriefPacket,
  buildMultiHopProofContract,
  type AssignmentBriefRoute,
} from '../src/server/assignment-brief.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import { runPhase0Recon } from '../src/server/phase0-recon.ts'
import { MULTIHOP_CHAINS_SKILL, clearSkillsCache, loadSkill } from '../src/server/skills.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import { makeLabGrant, makeStore, setupApprovedRun, withEnv } from './v4-tier-helpers.ts'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

test('1a. buildAssignmentBriefPacket serializes publicOrigins and multi-origin routes within budget', () => {
  const originA = 'https://portal.example.test'
  const originB = 'https://idp.example.test'
  const originC = 'https://exports.example.test'

  // Single-origin brief omits publicOrigins and stays <= 1.5 KB.
  const single = buildAssignmentBriefPacket({
    missionKind: 'class_scan',
    origin: originA,
    publicOrigins: [originA],
    routes: [{ method: 'GET', path: '/api/items', riskScore: 60 }],
  })
  assert.ok(single.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES)
  const parsedSingle = JSON.parse(single.text) as { publicOrigins?: string[]; routes: AssignmentBriefRoute[] }
  assert.equal(parsedSingle.publicOrigins, undefined, 'single-origin brief must omit publicOrigins')

  // Multi-origin brief serializes publicOrigins and preserves routes across EVERY approved origin.
  const multiRoutes: AssignmentBriefRoute[] = []
  for (let i = 1; i <= 5; i += 1) {
    multiRoutes.push({ origin: originA, method: 'POST', path: `/api/a/route-${i}`, riskScore: 95 - i })
    multiRoutes.push({ origin: originB, method: 'POST', path: `/api/b/route-${i}`, riskScore: 80 - i })
    multiRoutes.push({ origin: originC, method: 'GET', path: `/api/c/route-${i}`, riskScore: 70 - i })
  }
  const multi = buildAssignmentBriefPacket({
    missionKind: 'class_scan',
    origin: originA,
    publicOrigins: [originA, originB, originC],
    routes: multiRoutes,
  })
  assert.ok(
    multi.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
    `multi-origin brief exceeded 4 KB cap: ${multi.bytes} B`,
  )
  const parsedMulti = JSON.parse(multi.text) as {
    origin: string
    publicOrigins?: string[]
    routes: AssignmentBriefRoute[]
  }
  assert.deepEqual(parsedMulti.publicOrigins, [originA, originB, originC])
  const representedOrigins = new Set(parsedMulti.routes.map(r => r.origin))
  assert.equal(representedOrigins.has(originA), true, 'must include routes for originA')
  assert.equal(representedOrigins.has(originB), true, 'must include routes for sibling originB')
  assert.equal(representedOrigins.has(originC), true, 'must include routes for sibling originC')
  // Round-robin interleaving places top route of each origin near the front.
  assert.deepEqual(
    parsedMulti.routes.slice(0, 3).map(r => r.origin),
    [originA, originB, originC],
  )
})

test('1b. ExecReconPlanner.assignmentBriefForStep exposes sibling origins, top routes per origin, and sibling resourceSamples to Grey-Box workers', async t => {
  const { storage } = makeStore(t, 'kovo-v8-m2-gb-multi-')
  const originA = 'https://gateway.example.test'
  const originB = 'https://auth-idp.example.test'
  const originC = 'https://worker-export.example.test'
  const setup = await setupApprovedRun(storage, { seeds: [originA, originB, originC], tier: 3, budgetRequests: 900 })
  storage.updateRun(setup.runId, { phase: 'investigation', status: 'running' })

  // Seed 6 endpoints per origin so per-origin cap (<= 4 per origin) and multi-origin discovery are exercised.
  for (const [origin, prefix, baseRisk] of [
    [originA, '/api/gw', 95],
    [originB, '/api/idp', 85],
    [originC, '/api/exp', 75],
  ] as const) {
    for (let i = 1; i <= 6; i += 1) {
      storage.upsertEndpoint({
        runId: setup.runId,
        origin,
        method: i % 2 === 0 ? 'POST' : 'GET',
        pathTemplate: `${prefix}/r${i}`,
        source: 'spa_crawl',
        riskScore: baseRisk - i,
      })
    }
  }

  // Seed resource samples on sibling origins B and C (not just targetOrigin A).
  storage.recordResourceSample({
    runId: setup.runId,
    origin: originB,
    ownerPersona: 'actor_low',
    resourceKey: 'inviteId',
    resourceId: 'inv-sibling-b-101',
    endpoint: '/api/idp/r1',
    method: 'GET',
  })
  storage.recordResourceSample({
    runId: setup.runId,
    origin: originC,
    ownerPersona: 'actor_low',
    resourceKey: 'exportId',
    resourceId: 'exp-sibling-c-202',
    endpoint: '/api/exp/r1',
    method: 'GET',
  })

  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const internals = execution as unknown as Record<string, (...args: unknown[]) => unknown>
  const briefText = internals.assignmentBriefForStep({
    run: storage.run(setup.runId),
    step: {
      id: 'step-gb-multi',
      title: 'Wave-1 grey-box scan on gateway',
      hypothesis: 'Audit authorization boundaries across gateway endpoints.',
      category: 'broken-access-control',
      dependsOnFactIds: [],
      dependsOnStepIds: [],
    },
    targetOrigins: [originA],
    personas: [{ handle: 'actor_low', roleLabel: 'member (org_b)' }],
    parentFacts: [],
    confirmed: [],
    detLeads: [],
    maxTurns: 18,
  }) as string | undefined

  assert.ok(briefText, 'multi-origin Grey-Box brief must render')
  assert.ok(Buffer.byteLength(briefText!, 'utf8') <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)
  const parsed = JSON.parse(briefText!) as {
    origin: string
    publicOrigins?: string[]
    routes: AssignmentBriefRoute[]
    personas?: Array<{ handle: string; harvestedIds?: string[] }>
  }
  assert.equal(parsed.origin, originA)
  assert.deepEqual(parsed.publicOrigins, [originA, originB, originC])

  const countsByOrigin = new Map<string, number>()
  for (const r of parsed.routes) {
    assert.ok(r.origin, `multi-origin route ${r.method} ${r.path} must include origin`)
    countsByOrigin.set(r.origin!, (countsByOrigin.get(r.origin!) ?? 0) + 1)
  }
  assert.ok((countsByOrigin.get(originA) ?? 0) >= 1 && (countsByOrigin.get(originA) ?? 0) <= 4)
  assert.ok((countsByOrigin.get(originB) ?? 0) >= 1 && (countsByOrigin.get(originB) ?? 0) <= 4)
  assert.ok((countsByOrigin.get(originC) ?? 0) >= 1 && (countsByOrigin.get(originC) ?? 0) <= 4)
  assert.ok(parsed.routes.length <= 20)

  const actor = parsed.personas?.find(p => p.handle === 'actor_low')
  assert.ok(actor, 'persona must be present')
  assert.ok(actor!.harvestedIds?.includes('inv-sibling-b-101'), 'must include sibling originB resourceSample')
  assert.ok(actor!.harvestedIds?.includes('exp-sibling-c-202'), 'must include sibling originC resourceSample')
})

test('1c. workerInvestigationPrompt surfaces approved publicOrigins alongside targetOrigins', () => {
  const originA = 'https://gateway.example.test'
  const originB = 'https://idp.example.test'

  const multiPrompt = JSON.parse(workerInvestigationPrompt({
    goal: 'Audit multi-service app',
    step: {
      id: 'step-1',
      title: 'Grey-box Wave-1 audit',
      hypothesis: 'Check authorization boundaries.',
      category: 'broken-access-control',
      skills: [],
    },
    origins: [originA],
    publicOrigins: [originA, originB],
    capabilityTier: 3,
    maxTurns: 18,
  })) as { targetOrigins: string[]; publicOrigins?: string[] }

  assert.deepEqual(multiPrompt.targetOrigins, [originA])
  assert.deepEqual(multiPrompt.publicOrigins, [originA, originB])

  const singlePrompt = JSON.parse(workerInvestigationPrompt({
    goal: 'Audit single-service app',
    step: {
      id: 'step-2',
      title: 'Single-origin audit',
      hypothesis: 'Check authz.',
      category: 'broken-access-control',
      skills: [],
    },
    origins: [originA],
    publicOrigins: [originA],
    capabilityTier: 3,
    maxTurns: 18,
  })) as { targetOrigins: string[]; publicOrigins?: string[] }

  assert.deepEqual(singlePrompt.targetOrigins, [originA])
  assert.equal(singlePrompt.publicOrigins, undefined)
})

test('2a. summarizeKovoVerifyOutcome treats checkpoint_only as failure, keeps usageHint, and omits sealedCapabilities/verifiedHops', () => {
  const rawHint = 'Sealed handles expire after this script ends. Run Hop 1..N + ctx.prove_composite in ONE script.'
  const summary = summarizeKovoVerifyOutcome({
    confirmed: false,
    reason: 'checkpoint_only',
    detail: 'Script sealed cap:hop_1:tok without calling ctx.prove_composite.',
    rejectedBy: 'checkpoint',
    missingEvidence: ['composite_receipt'],
    exitCode: 0,
    usageHint: rawHint,
    sealedCapabilities: [
      { handle: 'cap:hop_1:tok', kind: 'bearer_token', sha256Prefix: 'deadbeef12345678' },
    ],
    verifiedHops: [
      { hopReceiptId: 'hop_1', edgeId: 'edge_1', binding: 'value_binding', postconditionCapId: 'cap:hop_1:tok' },
    ],
  })

  assert.equal(summary.confirmed, false)
  assert.equal(summary.reason, 'checkpoint_only')
  assert.equal(summary.usageHint, rawHint, 'usageHint MUST be preserved on checkpoint_only')
  assert.equal(summary.exitCode, 0, 'isScriptFailure must be true for checkpoint_only')
  assert.equal(summary.sealedCapabilities, undefined, 'sealedCapabilities must NOT be echoed on checkpoint_only')
  assert.equal(summary.verifiedHops, undefined, 'verifiedHops must NOT be echoed on checkpoint_only')

  // Fallback usageHint is still emitted when verdict omits usageHint on checkpoint_only.
  const fallbackSummary = summarizeKovoVerifyOutcome({
    confirmed: false,
    reason: 'checkpoint_only',
    detail: 'No composite receipt.',
    exitCode: 0,
  })
  assert.ok(fallbackSummary.usageHint && /ctx\.prove_composite/.test(fallbackSummary.usageHint))
  assert.ok(fallbackSummary.usageHint && /http_request/.test(fallbackSummary.usageHint))
})

test('2b. createCheckpointOnlySessionGuard omits sealed metadata and trips circuit-breaker after 2 consecutive checkpoint_only calls', () => {
  assert.equal(CHECKPOINT_ONLY_CIRCUIT_BREAKER_THRESHOLD, 2)
  const guard = createCheckpointOnlySessionGuard()
  const sealed = [{ handle: 'cap:hop_1:tok', kind: 'bearer_token', sha256Prefix: 'abcdef1234567890' }]
  const hops = [{ hopReceiptId: 'hop_1', edgeId: 'edge_1', binding: 'value_binding' }]
  const baseCheckpointVerdict = {
    confirmed: false,
    reason: 'checkpoint_only',
    detail: 'No composite receipt recorded.',
    usageHint: 'Run all hops in ONE script ending in ctx.prove_composite.',
    exitCode: 0,
  }

  // 1st consecutive checkpoint_only: strips sealedCapabilities/verifiedHops, keeps usageHint, no circuit-breaker yet.
  const first = guard.summarizeOutcome({ verdict: baseCheckpointVerdict, sealedCapabilities: sealed, verifiedHops: hops })
  assert.equal(guard.consecutiveCount(), 1)
  assert.equal(first.sealedCapabilities, undefined)
  assert.equal(first.verifiedHops, undefined)
  assert.equal(first.usageHint, baseCheckpointVerdict.usageHint)
  assert.equal(/CIRCUIT BREAKER/.test(first.detail), false)

  // 2nd consecutive checkpoint_only: trips circuit-breaker directive in detail & usageHint.
  const second = guard.summarizeOutcome({ verdict: baseCheckpointVerdict, sealedCapabilities: sealed, verifiedHops: hops })
  assert.equal(guard.consecutiveCount(), 2)
  assert.equal(second.sealedCapabilities, undefined)
  assert.equal(second.verifiedHops, undefined)
  assert.match(second.detail, /CIRCUIT BREAKER/)
  assert.match(second.detail, /http_request/)
  assert.match(second.detail, /ctx\.prove_composite/)
  assert.match(second.usageHint ?? '', /CIRCUIT BREAKER/)
  assert.match(second.usageHint ?? '', /http_request/)

  // A non-checkpoint_only call resets the consecutive counter and preserves sealed metadata.
  const nonCheckpoint = guard.summarizeOutcome({
    verdict: {
      confirmed: false,
      reason: 'oracle_failed',
      detail: 'Composite receipt failed terminal stage.',
      exitCode: 0,
    },
    sealedCapabilities: sealed,
    verifiedHops: hops,
  })
  assert.equal(guard.consecutiveCount(), 0)
  assert.equal(nonCheckpoint.sealedCapabilities?.length, 1)
  assert.equal(nonCheckpoint.verifiedHops?.length, 1)

  // Next checkpoint_only starts at 1 again (no circuit-breaker until 2 consecutive).
  const afterReset = guard.summarizeOutcome({ verdict: baseCheckpointVerdict, sealedCapabilities: sealed, verifiedHops: hops })
  assert.equal(guard.consecutiveCount(), 1)
  assert.equal(/CIRCUIT BREAKER/.test(afterReset.detail), false)
})

test('3. Prompt, brief contract, and multihop-chains skill enforce terminal impact, attacker-only personas, dual-tenant classes, and zero v8 contamination', () => {
  const full = buildMultiHopProofContract(false, {
    missionKind: 'multihop_chain',
    origin: 'https://svc.example.test',
    routes: [{ method: 'POST', path: '/api/v1/exports', riskScore: 90 }],
  })
  const compact = buildMultiHopProofContract(true, {
    missionKind: 'class_scan',
    origin: 'https://svc.example.test',
    publicOrigins: ['https://svc.example.test', 'https://idp.example.test'],
  })
  const promptText = workerInvestigationPrompt({
    goal: 'Audit multi-service app',
    step: {
      id: 'step-mh',
      title: 'Cross-service chain verification',
      hypothesis: 'Investigate cross-tenant pivot.',
      category: 'chain',
      skills: ['multihop-chains'],
    },
    origins: ['https://svc.example.test'],
    publicOrigins: ['https://svc.example.test', 'https://idp.example.test'],
    capabilityTier: 3,
    maxTurns: 20,
  })
  clearSkillsCache()
  const skill = loadSkill(MULTIHOP_CHAINS_SKILL)
  assert.ok(skill, 'multihop-chains skill must load')

  const surfaces = [
    { name: 'full contract', text: JSON.stringify(full) },
    { name: 'compact contract', text: JSON.stringify(compact) },
    { name: 'workerInvestigationPrompt', text: promptText },
    { name: 'multihop-chains.md', text: skill!.content },
  ]
  for (const surface of surfaces) {
    assert.match(surface.text, /terminalHopId/, `${surface.name} must instruct chaining to terminalHopId`)
    assert.match(surface.text, /privileged|victim\/owner\/admin/i, `${surface.name} must reserve privileged personas for controls`)
    assert.doesNotMatch(surface.text, /cross_tenant_data_access/, `${surface.name} must NOT mention unmapped cross_tenant_data_access`)
    assert.match(surface.text, /arm(?:\\?["'])?\s*:\s*\\?["']control\\?["']/, `${surface.name} must explicitly show { arm: "control" } for negative controls`)
  }
  for (const contractSurface of surfaces.slice(0, 2)) {
    assert.match(contractSurface.text, /dual_tenant_abac/, `${contractSurface.name} must mention dual_tenant_abac for dual-tenant chains`)
    assert.match(contractSurface.text, /own[- ]tenant/i, `${contractSurface.name} must forbid proving own-tenant resource reads`)
  }

  // Zero v8 benchmark contamination across production source and skills.
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `v8 contamination hits: ${JSON.stringify(scan.hits)}`)
})

test('2c. createCheckpointOnlySessionGuard hard-blocks non-proof scripts after >= 2 checkpoint_only calls before Docker execution', () => {
  const guard = createCheckpointOnlySessionGuard()
  const baseCheckpointVerdict = {
    confirmed: false,
    reason: 'checkpoint_only',
    detail: 'No composite receipt recorded.',
    exitCode: 0,
  }
  const sealOnlyScript = `const ex = await ctx.http_send('/api/token', { as: 'actor_low', role: 'probe' }); await ctx.seal_capability({ exchange: ex, slot: 'tok', jsonPath: '$.token' })`

  // Below threshold (< 2): never hard-blocks yet.
  assert.equal(guard.shouldBlockCheckpointOnlyScript(sealOnlyScript), false)
  guard.summarizeOutcome({ verdict: baseCheckpointVerdict, sealedCapabilities: [], verifiedHops: [] })
  assert.equal(guard.shouldBlockCheckpointOnlyScript(sealOnlyScript), false)

  // At threshold (>= 2): non-proof script is hard-blocked before Docker.
  guard.summarizeOutcome({ verdict: baseCheckpointVerdict, sealedCapabilities: [], verifiedHops: [] })
  assert.equal(guard.shouldBlockCheckpointOnlyScript(sealOnlyScript), true)

  const blocked = guard.buildBlockedOutcome()
  assert.equal(blocked.confirmed, false)
  assert.equal(blocked.blocked, true)
  assert.equal(blocked.reason, 'checkpoint_blocked')
  assert.match(blocked.detail, /http_request/)
  assert.match(blocked.detail, /ctx\.prove_composite/)
  assert.match(blocked.usageHint ?? '', /ctx\.prove_composite/)

  // Scripts containing any proof marker pass the pre-execution gate so real proofs still run.
  for (const proofScript of [
    'await ctx.prove_composite({ chainId: "c1" })',
    'await ctx.proveComposite({ chainId: "c1" })',
    'await ctx.prove_access_boundary({ route: "/api/x" })',
    'return ctx.result({ title: "ok" })',
    'const x = compositeReceipt',
  ]) {
    assert.equal(guard.shouldBlockCheckpointOnlyScript(proofScript), false, `proof script must not be blocked: ${proofScript}`)
  }

  // After a real proof attempt resets the streak, non-proof scripts are no longer blocked until 2 consecutive checkpoint_only calls again.
  guard.summarizeOutcome({
    verdict: { confirmed: false, reason: 'oracle_failed', detail: 'Composite receipt failed terminal stage.', exitCode: 0 },
    sealedCapabilities: [],
    verifiedHops: [],
  })
  assert.equal(guard.consecutiveCount(), 0)
  assert.equal(guard.shouldBlockCheckpointOnlyScript(sealOnlyScript), false)
})

test('1d. Multi-origin 4KB brief reduction preserves >= 1 route per approved publicOrigin and avoids high-risk origin starvation', async t => {
  const originA = 'https://portal.example.test'
  const originB = 'https://idp.example.test'
  const originC = 'https://exports.example.test'

  // Force tight 4KB reduction with heavy baseline, confirmed refs, harvestedIds, linkedRoutes, and hopCheckpoint.
  const heavy = buildAssignmentBriefPacket({
    missionKind: 'class_scan',
    origin: originA,
    publicOrigins: [originA, originB, originC],
    routes: [
      { origin: originA, method: 'POST', path: '/api/a/one', riskScore: 95 },
      { origin: originA, method: 'POST', path: '/api/a/two', riskScore: 94 },
      { origin: originB, method: 'POST', path: '/api/b/one', riskScore: 80 },
      { origin: originB, method: 'POST', path: '/api/b/two', riskScore: 79 },
      { origin: originC, method: 'GET', path: '/api/c/one', riskScore: 70 },
      { origin: originC, method: 'GET', path: '/api/c/two', riskScore: 69 },
    ],
    linkedRoutes: Array.from({ length: 8 }, (_, i) => ({ method: 'GET', path: `/api/linked/item-${i}`, riskScore: 60 })),
    personas: [
      { handle: 'actor_low', role: 'member (org_b)', harvestedIds: ['id-100001', 'id-100002', 'id-100003', 'id-100004', 'id-100005', 'id-100006'] },
      { handle: 'actor_two', role: 'viewer (org_b)', harvestedIds: ['id-200001', 'id-200002', 'id-200003', 'id-200004'] },
    ],
    baseline: {
      status: 200,
      topLevelKeys: Array.from({ length: 12 }, (_, i) => `baseline_field_key_${i}`),
      sampleNumericOrStateFields: Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`state_metric_${i}`, `sample_value_${i}_abcdef`])),
    },
    alreadyConfirmedOnOrigin: Array.from({ length: 20 }, (_, i) => ({
      method: 'GET',
      path: `/api/already/confirmed/route-${i}`,
      param: `param_${i}`,
      cwe: 'CWE-639',
      findingId: `fnd-${i}`,
    })),
    hopCheckpoint: {
      branchKey: 'branch-multi-origin-1',
      depth: 2,
      targetHop: 3,
      mode: 'pivot',
      verifiedHops: [{ hop: 1, receiptId: 'ex-hop-1', capId: 'cap:hop_1:tok', kind: 'scoped_token', surface: 'http', at: '/api/a/one', binding: 'value_binding' }],
      capabilityHandles: ['cap:hop_1:tok'],
      nextGoal: { endpoint: '/api/b/one', goal: 'Advance cross-service capability into sibling origin and confirm terminal impact.' },
    },
  })
  assert.ok(heavy.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)
  const parsedHeavy = JSON.parse(heavy.text) as { routes: AssignmentBriefRoute[] }
  const keptOrigins = new Set(parsedHeavy.routes.map(r => r.origin))
  assert.equal(keptOrigins.has(originA), true, 'originA route must survive 4KB reduction')
  assert.equal(keptOrigins.has(originB), true, 'sibling originB route must survive 4KB reduction')
  assert.equal(keptOrigins.has(originC), true, 'sibling originC route must survive 4KB reduction')

  // Starvation check: 150 higher-risk endpoints on originA must NOT crowd out lower-risk sibling origins B & C.
  const { storage } = makeStore(t, 'kovo-v8-m2-gb-starve-')
  const setup = await setupApprovedRun(storage, { seeds: [originA, originB, originC], tier: 3, budgetRequests: 900 })
  storage.updateRun(setup.runId, { phase: 'investigation', status: 'running' })
  for (let i = 0; i < 150; i += 1) {
    storage.upsertEndpoint({ runId: setup.runId, origin: originA, method: 'POST', pathTemplate: `/api/a/high-${i}`, source: 'spa_crawl', riskScore: 95 })
  }
  storage.upsertEndpoint({ runId: setup.runId, origin: originB, method: 'GET', pathTemplate: '/api/b/low-risk', source: 'spa_crawl', riskScore: 40 })
  storage.upsertEndpoint({ runId: setup.runId, origin: originC, method: 'GET', pathTemplate: '/api/c/low-risk', source: 'spa_crawl', riskScore: 35 })

  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const internals = execution as unknown as Record<string, (...args: unknown[]) => unknown>
  const briefText = internals.assignmentBriefForStep({
    run: storage.run(setup.runId),
    step: { id: 'step-starve', title: 'Wave-1 scan', hypothesis: 'Audit multi-origin surface.', category: 'broken-access-control', dependsOnFactIds: [], dependsOnStepIds: [] },
    targetOrigins: [originA],
    personas: [{ handle: 'actor_low', roleLabel: 'member (org_b)' }],
    parentFacts: [],
    confirmed: [],
    detLeads: [],
    maxTurns: 18,
  }) as string | undefined
  assert.ok(briefText)
  const parsedStarve = JSON.parse(briefText!) as { routes: AssignmentBriefRoute[] }
  assert.equal(parsedStarve.routes.some(r => r.origin === originB && r.path === '/api/b/low-risk'), true, 'originB route must not be starved')
  assert.equal(parsedStarve.routes.some(r => r.origin === originC && r.path === '/api/c/low-risk'), true, 'originC route must not be starved')
})

test('4. Phase-0 discovery prefers low-privilege personas and never escalates to owner/admin on non-root seed/API endpoints', async t => {
  const requestsSeen: Array<{ path: string; auth: string }> = []
  const srv = createServer((req, res) => {
    const urlPath = (req.url ?? '/').split('?')[0] || '/'
    const auth = String(req.headers.authorization ?? '')
    requestsSeen.push({ path: urlPath, auth })
    if (urlPath === '/') {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end('<html><body><a href="/api/routes">Routes</a></body></html>')
      return
    }
    if (urlPath === '/api/routes' || urlPath === '/config.json' || urlPath === '/openapi.json') {
      if (auth === 'Bearer owner-tok' || auth === 'Bearer admin-tok') {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ secretAdminRoutes: ['/api/admin/export'] }))
        return
      }
      res.writeHead(403, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'forbidden' }))
      return
    }
    res.writeHead(404, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ error: 'not found' }))
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => { srv.closeAllConnections(); srv.close(() => r()) }))
  await once(srv, 'listening')
  const origin = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`

  const { storage } = makeStore(t, 'kovo-v8-m2-phase0-priv-')
  const setup = await setupApprovedRun(storage, { seeds: [origin], budgetRequests: 400 })
  const grant = makeLabGrant(origin, { tier: 2 })
  grant.personas = new Map([
    ['owner_a', { id: 'p-owner', handle: 'owner_a', roleLabel: 'owner (org_a)', originAllowlist: [origin], authKind: 'bearer', headerName: null, secret: 'owner-tok', canaryMarkers: [] }],
    ['admin_a', { id: 'p-admin', handle: 'admin_a', roleLabel: 'admin (org_a)', originAllowlist: [origin], authKind: 'bearer', headerName: null, secret: 'admin-tok', canaryMarkers: [] }],
    ['member_b', { id: 'p-member', handle: 'member_b', roleLabel: 'member (org_b)', originAllowlist: [origin], authKind: 'bearer', headerName: null, secret: 'member-tok', canaryMarkers: [] }],
  ])

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => runPhase0Recon({
    storage,
    runId: setup.runId,
    scopeRevision: setup.run.scopeRevision,
    tier: 2,
    origins: [origin],
    // Intentionally pass high-priv personas first to verify Phase-0 sorts low-priv first internally.
    personas: ['owner_a', 'admin_a', 'member_b'],
    budgetRequests: 400,
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant,
    signal: AbortSignal.timeout(15_000),
  }))

  const nonRootPrivileged = requestsSeen.filter(
    r => r.path !== '/' && (r.auth === 'Bearer owner-tok' || r.auth === 'Bearer admin-tok'),
  )
  assert.deepEqual(
    nonRootPrivileged,
    [],
    `Phase-0 must never escalate to owner/admin personas on non-root endpoints, saw: ${JSON.stringify(nonRootPrivileged)}`,
  )
  assert.equal(
    requestsSeen.some(r => r.path === '/api/routes' && r.auth === 'Bearer member-tok'),
    true,
    'Phase-0 must probe non-root endpoints using low-privilege persona member_b',
  )
})
