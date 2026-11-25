/**
 * v8 Queue #26 Multi-Hop Chain Synthesis & Crypto/Async Adoption Tests.
 *
 * Proves (Docker-free, real SQLite WAL `Store`, zero benchmark contamination):
 *  1. Fix A (`codeAuditPrompt` + `code-auditor` system instructions):
 *     - Prioritizes end-to-end 3-5 hop cross-service causal chains using the pre-indexed
 *       multi-service route/guard/sink digest with explicit `Hop 1 -> Hop 2 -> Hop 3 -> Hop 4`
 *       formatting while preserving incremental `record_fact(kind="code_audit_suspect")` rules.
 *  2. Fix B (`convertCodeAuditSuspectsToChainSteps`):
 *     - Attaches compact bounded "Cross-Service Sibling Leads" context blocks (up to 4 other
 *       distinct suspects with route, file:line, and sinkKind) and links their IDs in
 *       `dependsOnFactIds` (primary suspect at index 0, bounded <= 5 total fact IDs).
 *     - Synthesizes up to 2 composite multi-service chain steps when complementary sink categories
 *       coexist (outbound-fetch/SSRF + internal signing/webhook; info-disclosure + auth/session +
 *       privileged mutation), ordered at top priority ahead of single-suspect steps while staying
 *       bounded to `CODE_AUDIT_WAVE1_MAX_STEPS = 6`.
 *     - Synthesizes 0 composites for homogeneous single-category batches and remains idempotent
 *       across repeated invocations.
 *     - Keeps `buildAssignmentBriefPacket` bounded <= 4 KB (`ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE`).
 *  3. Fix C (`workerInvestigationPrompt`, `GUARDIAN_VERIFY_*`, `src/skills/multihop-chains.md`):
 *     - Instructs multi-hop workers never to stop at intermediate single-hop disclosures/handles
 *       when downstream cross-service/auth/state-machine pivots are reachable.
 *     - Explicitly prohibits cross-tenant probe-arm collusion (single starting low-privilege
 *       persona or anonymous/derived credential; target-tenant persona only for baseline/readback).
 *     - Provides a copy-pasteable 4-hop `ctx.seal_capability` -> `ctx.hmac_sign`/`ctx.jwt_sign` +
 *       `ctx.await_async` -> `ctx.prove_composite` recipe in `src/skills/multihop-chains.md` whose
 *       receipt shape validates against `compositeProofReceiptSchema`, stays inside all prompt
 *       byte/line budgets, and passes `scanSourceTreeForContamination` with zero hits.
 */
import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { test } from 'node:test'

import {
  GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
  GUARDIAN_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN,
  GUARDIAN_VERIFY_TOOL_DESCRIPTION,
  codeAuditPrompt,
  guardianVerifyHelperGuidance,
  guardianVerifyPromptHint,
  workerInvestigationPrompt,
  workerSessionInstructions,
} from '../src/server/agent-prompts.ts'
import {
  ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
  buildAssignmentBriefPacket,
} from '../src/server/assignment-brief.ts'
import { compositeProofReceiptSchema } from '../src/server/composite-receipt.ts'
import {
  CODE_AUDIT_WAVE1_MAX_STEPS,
  MAX_CODE_AUDIT_SIBLING_LEADS,
  MAX_SYNTHESIZED_CODE_AUDIT_COMPOSITE_STEPS,
  chainLaneDispatchRank,
  classifyDispatchLane,
  convertCodeAuditSuspectsToChainSteps,
  isMultiHopChainStep,
  planRoundRobinDispatch,
} from '../src/server/exec-dispatch.ts'
import {
  MULTIHOP_CHAINS_SKILL,
  clearSkillsCache,
  loadSkill,
  selectPreInjectionSkills,
} from '../src/server/skills.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const REPO_ROOT = resolve(new URL('..', import.meta.url).pathname)
const ORIGIN = 'https://saas.example.invalid'

// ============================================================================
// 1. Fix A: codeAuditPrompt & code-auditor end-to-end 3-5 hop synthesis policy
// ============================================================================

test('Fix A: codeAuditPrompt and code-auditor instructions prioritize 3-5 hop cross-service causal chains', () => {
  const prompt = codeAuditPrompt({
    goal: 'Audit mounted multi-service repositories.',
    capabilityTier: 2,
    approvedOrigins: [ORIGIN],
    mountedRepos: ['acme-platform'],
    maxTurns: 8,
  })
  const parsed = JSON.parse(prompt) as {
    recordingPolicy?: { mode?: string; rule?: string; priorityOrder?: string[] }
    chainSynthesisPolicy?: { goal?: string; compositionPattern?: string; hypothesisFormat?: string }
  }

  assert.equal(parsed.recordingPolicy?.mode, 'incremental')
  assert.ok(Array.isArray(parsed.recordingPolicy?.priorityOrder))
  assert.match(parsed.recordingPolicy!.priorityOrder![0]!, /3-5 hop cross-service causal chains/i)
  assert.ok(parsed.chainSynthesisPolicy, 'codeAuditPrompt must include chainSynthesisPolicy')
  assert.match(parsed.chainSynthesisPolicy!.goal ?? '', /3-5 hop cross-service causal chains/i)
  assert.match(parsed.chainSynthesisPolicy!.goal ?? '', /route\/guard\/sink digest/i)
  assert.match(parsed.chainSynthesisPolicy!.compositionPattern ?? '', /Entry\/Leak\/Outbound-Fetch -> Internal\/Signing\/Invite\/Cache Pivot -> Forged Session\/Webhook\/Export -> Cross-Tenant Data or Unauthorized State Mutation/)
  assert.match(parsed.chainSynthesisPolicy!.hypothesisFormat ?? '', /Hop 1.*->.*Hop 2.*->.*Hop 3.*->.*Hop 4/)

  const instructions = workerSessionInstructions('code-auditor')
  assert.match(instructions, /3-5 hop cross-service chain synthesis/i)
  assert.match(instructions, /route\/guard\/sink digest/i)
  assert.match(instructions, /Hop 1 -> Hop 2 -> Hop 3 -> Hop 4/)
  assert.match(instructions, /Record incrementally/)
})

// ============================================================================
// 2. Fix B: Sibling Leads + Composite Multi-Service Chain Synthesis in Wave 1
// ============================================================================

test('Fix B: convertCodeAuditSuspectsToChainSteps synthesizes up to 2 composite chains and attaches bounded Cross-Service Sibling Leads', async (t) => {
  assert.equal(MAX_CODE_AUDIT_SIBLING_LEADS, 4)
  assert.equal(MAX_SYNTHESIZED_CODE_AUDIT_COMPOSITE_STEPS, 2)

  const { storage } = makeStore(t)
  const { run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const auditor = storage.makeWorker(run, 'threat_model', asset, 'Source-First Code Audit', 'Audit')

  const fSsrf = storage.addFact(run, auditor, {
    kind: 'code_audit_suspect',
    origin: ORIGIN,
    summary: 'Outbound fetch SSRF in render worker follows redirects to internal service.',
    data: {
      subkind: 'code_audit_suspect',
      file: 'services/renderer/fetch.ts',
      line: 52,
      routeOrAction: 'POST /api/v1/render/preview',
      sinkKind: 'outbound_fetch',
      authCheck: 'member',
      ownershipCheck: 'missing',
      hypothesis: 'Renderer fetches caller-controlled URL without internal egress block.',
    },
  })
  const fWebhook = storage.addFact(run, auditor, {
    kind: 'code_audit_suspect',
    origin: ORIGIN,
    summary: 'Internal webhook signing endpoint accepts unauthenticated requests from internal network.',
    data: {
      subkind: 'code_audit_suspect',
      file: 'services/webhooks/signer.ts',
      line: 88,
      routeOrAction: 'POST /internal/webhooks/sign',
      sinkKind: 'webhook',
      authCheck: 'network_only',
      ownershipCheck: 'missing',
      hypothesis: 'Internal HMAC signer signs arbitrary webhook payloads when reached via SSRF.',
    },
  })
  const fLeak = storage.addFact(run, auditor, {
    kind: 'code_audit_suspect',
    origin: ORIGIN,
    summary: 'Diagnostic log endpoint discloses signing salt and invite token metadata across tenants.',
    data: {
      subkind: 'code_audit_suspect',
      file: 'services/diagnostics/logs.ts',
      line: 31,
      routeOrAction: 'GET /api/v1/diagnostics/audit',
      sinkKind: 'api_route',
      authCheck: 'member',
      ownershipCheck: 'missing',
      hypothesis: 'Directory/log disclosure exposes tenant invite metadata and signing salt.',
    },
  })
  const fInvite = storage.addFact(run, auditor, {
    kind: 'code_audit_suspect',
    origin: ORIGIN,
    summary: 'Invite token exchange mints session cookie without verifying caller tenant scope.',
    data: {
      subkind: 'code_audit_suspect',
      file: 'services/identity/invite.ts',
      line: 114,
      routeOrAction: 'POST /api/v1/auth/invite/accept',
      sinkKind: 'auth_config',
      authCheck: 'weak',
      ownershipCheck: 'missing',
      hypothesis: 'Accepts leaked/derived invite token and issues cross-tenant session.',
    },
  })
  const fExport = storage.addFact(run, auditor, {
    kind: 'code_audit_suspect',
    origin: ORIGIN,
    summary: 'Async batch export endpoint writes cross-tenant ledger records without tenant check.',
    data: {
      subkind: 'code_audit_suspect',
      file: 'services/billing/export.ts',
      line: 204,
      routeOrAction: 'POST /api/v1/billing/export',
      sinkKind: 'upload_storage',
      authCheck: 'session',
      ownershipCheck: 'missing',
      hypothesis: 'Generates downloadable foreign-tenant billing export once privileged session or webhook arrives.',
    },
  })
  const fLedger = storage.addFact(run, auditor, {
    kind: 'code_audit_suspect',
    origin: ORIGIN,
    summary: 'Ledger transfer approval omits distinct approver check allowing self-approval.',
    data: {
      subkind: 'code_audit_suspect',
      file: 'services/billing/transfer.ts',
      line: 77,
      routeOrAction: 'POST /api/v1/ledger/approve',
      sinkKind: 'api_route',
      authCheck: 'session',
      ownershipCheck: 'missing',
      hypothesis: 'Creator can approve own transfer request across org boundary.',
    },
  })

  const suspects = [fSsrf, fWebhook, fLeak, fInvite, fExport, fLedger]
  const steps = convertCodeAuditSuspectsToChainSteps(storage, run, suspects, undefined, {
    maxSteps: CODE_AUDIT_WAVE1_MAX_STEPS,
    promoteMultiHop: true,
  })

  assert.equal(steps.length, CODE_AUDIT_WAVE1_MAX_STEPS, 'total promoted steps must stay bounded to 6')

  const composites = steps.filter(s => s.title.startsWith('Source audit composite chain ·'))
  const individuals = steps.filter(s => !s.title.startsWith('Source audit composite chain ·'))
  assert.equal(composites.length, 2, 'must synthesize 2 complementary composite multi-service chains')
  assert.equal(individuals.length, 4, 'remaining 4 Wave-1 slots must hold top individual suspect steps')

  // Composite #1 links Outbound/SSRF -> Signing/Webhook -> Terminal
  assert.match(composites[0]!.title, /Outbound\/SSRF -> Signing\/Webhook/i)
  assert.match(composites[0]!.hypothesis, /Hop 1 .* -> Hop 2 /)
  assert.ok(composites[0]!.dependsOnFactIds.includes(fSsrf.id))
  assert.ok(composites[0]!.dependsOnFactIds.includes(fWebhook.id))

  // Composite #2 links Disclosure -> Auth/Session -> Privileged Mutation
  assert.match(composites[1]!.title, /Disclosure -> Auth\/Session -> Privileged Mutation/i)
  assert.match(composites[1]!.hypothesis, /Hop 1 .* -> Hop 2 .* -> Hop 3 /)
  assert.ok(composites[1]!.dependsOnFactIds.includes(fLeak.id))
  assert.ok(composites[1]!.dependsOnFactIds.includes(fInvite.id))

  // Every step dispatches at top Rank 0 in the chain lane, and composites outrank individuals!
  for (const step of steps) {
    assert.equal(isMultiHopChainStep(step), true)
    assert.equal(classifyDispatchLane(step), 'chain')
    assert.equal(chainLaneDispatchRank(step), 0)
    assert.ok(step.dependsOnFactIds.length >= 2 && step.dependsOnFactIds.length <= MAX_CODE_AUDIT_SIBLING_LEADS + 1)
    assert.match(step.hypothesis, /ctx\.seal_capability/)
    assert.match(step.hypothesis, /ctx\.prove_composite/)
    assert.match(step.hypothesis, /never use a target-tenant persona on the probe arm/i)
    assert.match(step.hypothesis, /never stop at an intermediate info-disclosure/i)
  }

  // Individual steps carry bounded Cross-Service Sibling Leads summarizing up to 4 distinct siblings
  for (const step of individuals) {
    assert.match(step.hypothesis, /Cross-Service Sibling Leads/)
    const siblingMarkers = step.hypothesis.match(/\[S\d+\]/g) ?? []
    assert.ok(siblingMarkers.length >= 1 && siblingMarkers.length <= MAX_CODE_AUDIT_SIBLING_LEADS)
    assert.match(step.hypothesis, /sink=/)
    assert.ok(step.hypothesis.length < 2200, `step hypothesis must remain compact (got ${step.hypothesis.length} chars)`)
  }

  // Wave-1 round-robin dispatch places synthesized composite chains FIRST!
  const dispatchPlan = planRoundRobinDispatch(steps, 3)
  assert.equal(dispatchPlan.ordered[0]!.id, composites[0]!.id)
  assert.equal(dispatchPlan.ordered[1]!.id, composites[1]!.id)

  // Idempotency: re-running on the same suspect batch creates 0 duplicate steps!
  const rerun = convertCodeAuditSuspectsToChainSteps(storage, run, suspects, undefined, {
    maxSteps: CODE_AUDIT_WAVE1_MAX_STEPS,
    promoteMultiHop: true,
  })
  assert.equal(rerun.length, 0, 're-running convertCodeAuditSuspectsToChainSteps must be idempotent')

  // Assignment brief stays strictly <= 4 KB even for a multi-hop composite step with 5 linked facts.
  const briefPacket = buildAssignmentBriefPacket({
    missionKind: 'multihop_chain',
    origin: ORIGIN,
    routes: [
      { method: 'POST', path: '/api/v1/render/preview', riskScore: 95 },
      { method: 'POST', path: '/internal/webhooks/sign', riskScore: 95 },
      { method: 'POST', path: '/api/v1/billing/export', riskScore: 98 },
    ],
    personas: [
      { handle: 'member_b', role: 'member (org_b)' },
      { handle: 'owner_a', role: 'owner (org_a)' },
    ],
  })
  assert.ok(briefPacket.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)
})

test('Fix B: homogeneous single-category suspects synthesize 0 composites while still linking compact sibling leads', async (t) => {
  const { storage } = makeStore(t)
  const { run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const auditor = storage.makeWorker(run, 'threat_model', asset, 'Source-First Code Audit', 'Audit')

  const facts = [1, 2, 3].map(i =>
    storage.addFact(run, auditor, {
      kind: 'code_audit_suspect',
      origin: ORIGIN,
      summary: `Cross-tenant authz bypass on POST /api/v1/orders-${i}`,
      data: {
        subkind: 'code_audit_suspect',
        file: `services/api/orders-${i}.ts`,
        line: i * 10,
        routeOrAction: `POST /api/v1/orders-${i}`,
        sinkKind: 'api_route',
      },
    }),
  )

  const steps = convertCodeAuditSuspectsToChainSteps(storage, run, facts, undefined, {
    maxSteps: CODE_AUDIT_WAVE1_MAX_STEPS,
    promoteMultiHop: true,
  })
  assert.equal(steps.length, 3)
  assert.equal(steps.filter(s => s.title.startsWith('Source audit composite chain ·')).length, 0)
  for (const step of steps) {
    assert.equal(step.dependsOnFactIds.length, 3, 'primary + 2 siblings linked')
    assert.match(step.hypothesis, /Cross-Service Sibling Leads/)
  }
})

// ============================================================================
// 3. Fix C: Anti-Premature-Filing, No-Collusion & Crypto/Async Recipe + Clean Lint
// ============================================================================

test('Fix C: workerInvestigationPrompt, GUARDIAN_VERIFY guidance, and multihop-chains.md enforce no-premature-filing, single-origin probe arm, and crypto/async recipe', () => {
  // Budget invariants stay strictly satisfied.
  const guidance = guardianVerifyHelperGuidance()
  const hint = guardianVerifyPromptHint()
  const patternLines = GUARDIAN_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN.split('\n')
  assert.ok(
    Buffer.byteLength(guidance, 'utf8') <= GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
    `guidance ${Buffer.byteLength(guidance, 'utf8')} B > ${GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES} B`,
  )
  assert.ok(Buffer.byteLength(hint, 'utf8') <= 512, `hint ${Buffer.byteLength(hint, 'utf8')} B > 512 B`)
  assert.ok(patternLines.length <= 12, `pattern has ${patternLines.length} lines (must be <= 12)`)

  // Tool description, helper guidance, and active system prompt all enforce both rules.
  const sysPrompt = workerSessionInstructions('worker-investigation', { hasGuardianVerify: true })
  for (const [label, text] of [
    ['GUARDIAN_VERIFY_TOOL_DESCRIPTION', GUARDIAN_VERIFY_TOOL_DESCRIPTION],
    ['workerSessionInstructions', sysPrompt],
  ] as const) {
    assert.match(text, /NEVER stop at or file an intermediate single-hop info-disclosure/i, `${label} missing no-premature-filing rule`)
    assert.match(text, /ALL probe-arm hops MUST run as a single starting low-privilege persona/i, `${label} missing single-origin probe-arm rule`)
    assert.match(text, /NEVER use a target-tenant persona on the probe arm to mint handles/i, `${label} missing anti-collusion rule`)
  }
  assert.match(guidance, /Never stop at a single-hop disclosure\/handle/i)
  assert.match(guidance, /ONE low-priv\/cross-tenant persona/i)

  // workerInvestigationPrompt emits multiHopDirectives for multi-hop steps and omits it for single-hop steps.
  const multiHopPrompt = JSON.parse(workerInvestigationPrompt({
    goal: 'Verify cross-service chain',
    step: {
      id: 'step-mh',
      title: 'Source audit composite chain · Outbound/SSRF -> Signing/Webhook',
      hypothesis: 'Hop 1 -> Hop 2 -> Hop 3',
      category: 'broken-access-control',
      skills: ['source-first-audit', 'multihop-chains', 'chain-primitives'],
    },
    origins: [ORIGIN],
    capabilityTier: 2,
    maxTurns: 12,
  })) as { multiHopDirectives?: { noPrematureSingleHop?: string; singleOriginProbeArm?: string; cryptoAndAsyncHelpers?: string } }
  assert.ok(multiHopPrompt.multiHopDirectives, 'multi-hop worker prompt must include multiHopDirectives')
  assert.match(multiHopPrompt.multiHopDirectives!.noPrematureSingleHop ?? '', /ctx\.seal_capability.*ctx\.prove_composite/i)
  assert.match(multiHopPrompt.multiHopDirectives!.singleOriginProbeArm ?? '', /single starting low-privilege persona/i)
  assert.match(multiHopPrompt.multiHopDirectives!.singleOriginProbeArm ?? '', /never use a target-tenant persona on the probe arm/i)
  assert.match(multiHopPrompt.multiHopDirectives!.cryptoAndAsyncHelpers ?? '', /ctx\.hmac_sign.*ctx\.jwt_sign.*ctx\.await_async/)

  const singleHopPrompt = JSON.parse(workerInvestigationPrompt({
    goal: 'Check single route',
    step: {
      id: 'step-sh',
      title: 'SQLi check on /api/v1/search',
      hypothesis: 'Verify boolean differential on query parameter.',
      category: 'injection-input',
      skills: ['injection-sqli-nosqli'],
    },
    origins: [ORIGIN],
    capabilityTier: 2,
    maxTurns: 8,
  })) as { multiHopDirectives?: unknown }
  assert.equal(singleHopPrompt.multiHopDirectives, undefined, 'single-hop worker prompt must omit multiHopDirectives')

  // multihop-chains.md pre-injected excerpt (<= 1200 chars) + full copy-pasteable 4-hop crypto+async recipe.
  clearSkillsCache()
  const injected = selectPreInjectionSkills({
    profileSkills: ['bola-idor-race'],
    lane: 'chain',
    limit: 2,
  })
  const mhSkill = injected.find(s => s.name === MULTIHOP_CHAINS_SKILL)
  assert.ok(mhSkill, 'multihop-chains must be pre-injected for chain lane')
  assert.match(mhSkill!.excerpt, /No Collusion/i)
  assert.match(mhSkill!.excerpt, /No Premature Filing/i)
  assert.ok(mhSkill!.excerpt.includes('ctx.seal_capability'))
  assert.ok(mhSkill!.excerpt.includes('ctx.hmac_sign'))
  assert.ok(mhSkill!.excerpt.includes('ctx.jwt_sign'))
  assert.ok(mhSkill!.excerpt.includes('ctx.await_async'))
  assert.ok(mhSkill!.excerpt.includes('ctx.prove_composite'))
  assert.ok(mhSkill!.excerpt.includes('invariant_enforced_hardened'))

  const fullPlaybook = loadSkill(MULTIHOP_CHAINS_SKILL)?.content ?? ''
  assert.match(fullPlaybook, /Copy-Pasteable 4-Hop Crypto \+ Async Recipe/i)
  assert.ok(fullPlaybook.includes("chainId: 'chain-crypto-async-4hop'"))
  assert.ok(fullPlaybook.includes('ctx.hmac_sign({ secretHandle: keyCap.handle'))
  assert.ok(fullPlaybook.includes('ctx.jwt_sign({ secretHandle: keyCap.handle'))
  assert.ok(fullPlaybook.includes('ctx.await_async({'))
  assert.ok(fullPlaybook.includes("kind: 'derived_crypto_binding'"))
  assert.ok(fullPlaybook.includes("kind: 'async_pivot_binding'"))
  assert.ok(fullPlaybook.includes("kind: 'value_binding'"))

  // Validate the 4-hop recipe's CompositeProofReceipt structure directly against the live Zod schema.
  const recipeCheck = compositeProofReceiptSchema.safeParse({
    chainId: 'chain-crypto-async-4hop',
    terminalVulnClass: 'cross_surface_pivot',
    replayMode: 'fresh_clean_replay',
    hops: [
      {
        hopId: 'hop_1',
        surface: 'http',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/service-meta' },
        exchangeIds: ['ex-h1'],
        claimedDelta: 'Low-priv persona obtains intermediate signing material.',
        producedCapabilities: ['cap:hop_1:signing_key'],
        consumedCapabilities: [],
      },
      {
        hopId: 'hop_2',
        surface: 'webhook',
        target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/webhooks/trigger' },
        exchangeIds: ['ex-sig', 'ex-h2'],
        claimedDelta: 'Host-attested HMAC signature triggers privileged async export job.',
        producedCapabilities: ['cap:hop_2:job_id'],
        consumedCapabilities: ['cap:hop_1:signing_key'],
      },
      {
        hopId: 'hop_3',
        surface: 'async_job',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/jobs/status?corr=corr-1' },
        exchangeIds: ['ex-pol'],
        claimedDelta: 'Async worker converges and yields export capability.',
        producedCapabilities: ['cap:hop_3:export_tok'],
        consumedCapabilities: ['cap:hop_2:job_id'],
      },
      {
        hopId: 'hop_4',
        surface: 'http',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/exports/foreign-item' },
        exchangeIds: ['ex-read'],
        claimedDelta: 'Terminal cross-tenant business record retrieved via derived capability.',
        producedCapabilities: [],
        consumedCapabilities: ['cap:hop_3:export_tok'],
      },
    ],
    causalEdges: [
      { kind: 'derived_crypto_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sourceCapabilityId: 'cap:hop_1:signing_key', alg: 'sha256' },
      { kind: 'async_pivot_binding', fromHopId: 'hop_2', toHopId: 'hop_3', correlationId: 'corr-1', channel: 'poll_convergence', pollRecordId: 'poll-1' },
      { kind: 'value_binding', fromHopId: 'hop_3', toHopId: 'hop_4', capabilityHandle: 'cap:hop_3:export_tok' },
    ],
    terminalImpact: {
      terminalHopId: 'hop_4',
      claimedImpact: 'Unauthorized cross-tenant business record retrieved via 4-hop signing + async worker pivot.',
      preChainControlExchangeIds: ['ex-pre'],
      postChainReadbackExchangeIds: ['ex-read'],
    },
  })
  assert.equal(recipeCheck.success, true, `4-hop recipe receipt schema mismatch: ${JSON.stringify(recipeCheck)}`)

  // Zero v8 benchmark contamination across src/server/** and src/skills/**.
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `Unexpected contamination: ${JSON.stringify(scan.hits)}`)
  assert.deepEqual(scan.hits, [])
})
