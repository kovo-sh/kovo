/**
 * v8 Queue #30 End-to-End Multi-Stage Workflow Consolidation & Cross-Service Synthesis Tests.
 *
 * Verifies (Docker-free, real SQLite WAL `Store`, zero benchmark contamination):
 *  1. `kovoVerifyHelperGuidance()`, `KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN`,
 *     `workerInvestigationPrompt()`, `workerSessionInstructions()`, and `src/skills/multihop-chains.md`:
 *     - Instruct workers never to stop at intermediate artifacts (job creation, cache priming, or
 *       link/token generation) and always continue in the SAME script through `ctx.await_async`,
 *       `ctx.hmac_sign`/`ctx.jwt_sign`, or `ctx.prove_race_burst` to final readback/state change.
 *     - Teach white-box single-script consolidation (`Stage 1 -> Stage 2 -> Stage 3 -> Stage 4 ->
 *       ctx.prove_composite(...)` in ONE cohesive script once source routes are known).
 *     - Enforce `state_transition_binding` clean-control order (run baseline denied control
 *       `role: "control"` BEFORE Stage 1 or on a fresh untouched sibling entity).
 *     - Stay strictly within all prompt budgets (`kovoVerifyHelperGuidance() <= 2048 B`,
 *       `kovoVerifyPromptHint() <= 512 B`, pattern `<= 12` lines, pre-injected excerpt keeps
 *       all Section-1 directives including `invariant_enforced_hardened`).
 *     - Never reference nonexistent `ctx.race(` (always use live SDK `ctx.prove_race_burst`).
 *  2. `convertCodeAuditSuspectsToChainSteps`:
 *     - Synthesizes dedicated 3-5 stage cross-service composite workflows across:
 *       (a) outbound-request + signing/webhook,
 *       (b) cache/permission + async export/download,
 *       (c) directory/identity + state-change,
 *       (d) request-parsing + concurrent settlement.
 *     - Outlines `Stage 1 -> Stage 2 -> Stage 3 -> Terminal Verification` and reminds workers to
 *       verify all stages in ONE script with `ctx.seal_capability`,
 *       `ctx.hmac_sign`/`ctx.jwt_sign`/`ctx.await_async`/`ctx.prove_race_burst`, clean denied
 *       control BEFORE Stage 1, and `ctx.prove_composite`.
 *     - Remains idempotent and synthesizes 0 composites for homogeneous single-category batches.
 *  3. Zero v8 benchmark contamination across `src/server/**` and `src/skills/**`.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { test } from 'node:test'

import {
  KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
  KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN,
  KOVO_VERIFY_TOOL_DESCRIPTION,
  kovoVerifyHelperGuidance,
  kovoVerifyPromptHint,
  workerInvestigationPrompt,
  workerSessionInstructions,
} from '../src/server/agent-prompts.ts'
import {
  CODE_AUDIT_WAVE1_MAX_STEPS,
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
const ORIGIN = 'https://workflow.example.invalid'

test('Q30.1: prompts, tool guidance, and multihop-chains.md enforce single-script 3-5 stage workflows and clean-control ordering within strict budgets', () => {
  const guidance = kovoVerifyHelperGuidance()
  const hint = kovoVerifyPromptHint()
  const patternLines = KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN.split('\n')

  // Strict prompt/pattern byte and line budgets.
  assert.ok(
    Buffer.byteLength(guidance, 'utf8') <= KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
    `kovoVerifyHelperGuidance() is ${Buffer.byteLength(guidance, 'utf8')} B (> ${KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES} B)`,
  )
  assert.ok(Buffer.byteLength(hint, 'utf8') <= 512, `hint is ${Buffer.byteLength(hint, 'utf8')} B (> 512 B)`)
  assert.ok(patternLines.length <= 12, `pattern has ${patternLines.length} lines (> 12)`)

  // Helper guidance emphasizes single-script execution, no intermediate stub stops, and clean-control order.
  assert.match(guidance, /Run ALL stages in ONE script/i)
  assert.match(guidance, /job creation, or cache prime/i)
  assert.match(guidance, /ctx\.prove_race_burst/)
  assert.match(guidance, /clean denied control BEFORE Stage 1/i)

  // Pattern, tool description, and active system prompt teach all 3 Queue #30 rules.
  const sysPrompt = workerSessionInstructions('worker-investigation', { hasKovoVerify: true })
  for (const [label, text] of [
    ['KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN', KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN],
    ['KOVO_VERIFY_TOOL_DESCRIPTION', KOVO_VERIFY_TOOL_DESCRIPTION],
    ['workerSessionInstructions', sysPrompt],
  ] as const) {
    assert.match(text, /job creation, cache priming, or link\/token generation/i, `${label} missing no-intermediate-artifact rule`)
    assert.match(text, /SAME verification script/i, `${label} missing same-script continuation rule`)
    assert.match(text, /Stage 1 -> Stage 2 -> Stage 3 -> Stage 4 -> `ctx\.prove_composite/i, `${label} missing white-box single-script consolidation`)
    assert.match(text, /state_transition_binding.*clean-control order/i, `${label} missing state_transition_binding clean-control order`)
    assert.match(text, /BEFORE Stage 1/i, `${label} missing BEFORE Stage 1 control timing`)
    assert.match(text, /fresh untouched sibling entity/i, `${label} missing fresh sibling entity fallback`)
    assert.ok(text.includes('ctx.prove_race_burst'), `${label} must use live SDK ctx.prove_race_burst`)
    assert.equal(/\bctx\.race\b/.test(text), false, `${label} must not reference nonexistent ctx.race`)
  }

  // workerInvestigationPrompt surfaces singleScriptConsolidation + stateTransitionControlOrder on multi-hop steps
  // (including steps worded with "Stage 1 -> Stage 2") and omits them on single-hop steps.
  const stagePrompt = JSON.parse(workerInvestigationPrompt({
    goal: 'Verify multi-stage cross-service workflow',
    step: {
      id: 'step-stage-wf',
      title: 'Cross-service cache and async export verification',
      hypothesis: 'Stage 1 -> Stage 2 -> Stage 3 -> Terminal Verification',
      category: 'broken-access-control',
      skills: ['bola-idor-race'],
    },
    origins: [ORIGIN],
    capabilityTier: 2,
    maxTurns: 12,
  })) as {
    multiHopDirectives?: {
      noPrematureSingleHop?: string
      singleOriginProbeArm?: string
      cryptoAndAsyncHelpers?: string
      singleScriptConsolidation?: string
      stateTransitionControlOrder?: string
    }
  }
  assert.ok(stagePrompt.multiHopDirectives, 'Stage 1 -> Stage 2 step must receive multiHopDirectives')
  assert.match(stagePrompt.multiHopDirectives!.noPrematureSingleHop ?? '', /job creation, cache prime, or link\/token generation/i)
  assert.match(stagePrompt.multiHopDirectives!.cryptoAndAsyncHelpers ?? '', /ctx\.prove_race_burst/)
  assert.match(stagePrompt.multiHopDirectives!.singleScriptConsolidation ?? '', /ONE cohesive multi-stage kovo_verify script.*Stage 1 -> Stage 2 -> Stage 3 -> Stage 4 -> ctx\.prove_composite/i)
  assert.match(stagePrompt.multiHopDirectives!.stateTransitionControlOrder ?? '', /state_transition_binding.*role: "control".*BEFORE Stage 1.*fresh untouched sibling entity/i)

  const singlePrompt = JSON.parse(workerInvestigationPrompt({
    goal: 'Single route verification',
    step: {
      id: 'step-single',
      title: 'Single-endpoint header check',
      hypothesis: 'Check response policy on /api/v1/health.',
      category: 'misconfig-exposure',
      skills: ['false-positive-elimination'],
    },
    origins: [ORIGIN],
    capabilityTier: 2,
    maxTurns: 6,
  })) as { multiHopDirectives?: unknown }
  assert.equal(singlePrompt.multiHopDirectives, undefined)

  // multihop-chains.md pre-injected excerpt (< 1200 chars) and full playbook carry all new rules.
  clearSkillsCache()
  const preInjected = selectPreInjectionSkills({ profileSkills: ['bola-idor-race'], lane: 'chain', limit: 2 })
  const mhSkill = preInjected.find(s => s.name === MULTIHOP_CHAINS_SKILL)
  assert.ok(mhSkill, 'multihop-chains must be pre-injected for chain lane')
  assert.match(mhSkill!.excerpt, /Stage 1->2->3->4->`ctx\.prove_composite` in ONE script/i)
  assert.match(mhSkill!.excerpt, /job creation, cache prime, or link\/token stubs/i)
  assert.match(mhSkill!.excerpt, /BEFORE Stage 1.*state_transition_binding/i)
  assert.ok(mhSkill!.excerpt.includes('ctx.prove_race_burst'))
  assert.ok(mhSkill!.excerpt.includes('invariant_enforced_hardened'), 'Section 1 must stay compact so invariant_enforced_hardened stays in the 1200-char excerpt')

  const playbook = loadSkill(MULTIHOP_CHAINS_SKILL)?.content ?? ''
  assert.match(playbook, /White-Box Single-Script Consolidation/i)
  assert.match(playbook, /Clean-Control Order Rule/i)
  assert.match(playbook, /cleanSession=false/)
  assert.equal(/\bctx\.race\b/.test(playbook), false, 'multihop-chains.md must not reference nonexistent ctx.race')
})

test('Q30.2: convertCodeAuditSuspectsToChainSteps synthesizes cache/permission + async export and request-parsing + concurrent settlement workflows', async (t) => {
  const { storage } = makeStore(t)
  const { run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const auditor = storage.makeWorker(run, 'threat_model', asset, 'Source-First Code Audit', 'Audit')

  // Pair A: Cache/permission + async export/download
  const fCache = storage.addFact(run, auditor, {
    kind: 'code_audit_suspect',
    origin: ORIGIN,
    summary: 'Shared permission cache omits tenant key prefix allowing cross-tenant cache prime.',
    data: {
      subkind: 'code_audit_suspect',
      file: 'services/authz/perm-cache.ts',
      line: 44,
      routeOrAction: 'GET /api/v1/orgs/:orgId/permissions',
      sinkKind: 'api_route',
      authCheck: 'member',
      ownershipCheck: 'missing',
      hypothesis: 'Priming permission cache on own tenant populates shared cache key for target org.',
    },
  })
  const fAsyncExport = storage.addFact(run, auditor, {
    kind: 'code_audit_suspect',
    origin: ORIGIN,
    summary: 'Async export worker queues foreign org dataset and exposes downloadable file when ready.',
    data: {
      subkind: 'code_audit_suspect',
      file: 'services/exports/worker.ts',
      line: 118,
      routeOrAction: 'POST /api/v1/orgs/:orgId/exports',
      sinkKind: 'upload_storage',
      authCheck: 'cached_perm',
      ownershipCheck: 'missing',
      hypothesis: 'Export job runs asynchronously and serves generated archive via download route.',
    },
  })

  // Pair B: Request-parsing + concurrent settlement
  const fParser = storage.addFact(run, auditor, {
    kind: 'code_audit_suspect',
    origin: ORIGIN,
    summary: 'Gateway request parsing normalizes duplicate JSON keys differently from downstream validator.',
    data: {
      subkind: 'code_audit_suspect',
      file: 'services/gateway/parser.ts',
      line: 72,
      routeOrAction: 'POST /api/v1/settlements/submit',
      sinkKind: 'api_route',
      authCheck: 'member',
      ownershipCheck: 'weak',
      hypothesis: 'Request parser differential bypasses idempotency header check at gateway.',
    },
  })
  const fRace = storage.addFact(run, auditor, {
    kind: 'code_audit_suspect',
    origin: ORIGIN,
    summary: 'Concurrent settlement ledger credit lacks row lock allowing double-spend overcredit.',
    data: {
      subkind: 'code_audit_suspect',
      file: 'services/ledger/settlement.ts',
      line: 163,
      routeOrAction: 'POST /api/v1/ledger/settle',
      sinkKind: 'db_query',
      authCheck: 'member',
      ownershipCheck: 'missing',
      hypothesis: 'Parallel burst settlement requests over-credit balance without idempotency lock.',
    },
  })

  const steps = convertCodeAuditSuspectsToChainSteps(storage, run, [fCache, fAsyncExport, fParser, fRace], undefined, {
    maxSteps: CODE_AUDIT_WAVE1_MAX_STEPS,
    promoteMultiHop: true,
  })

  assert.equal(steps.length, 6, '2 composites + 4 individual suspects fill the 6-step Wave-1 budget')
  const composites = steps.filter(s => s.title.startsWith('Source audit composite chain ·'))
  assert.equal(composites.length, 2)

  // Composite 1: Cache/Permission -> Async Export/Download
  assert.match(composites[0]!.title, /Cache\/Permission -> Async Export\/Download/i)
  assert.ok(composites[0]!.dependsOnFactIds.includes(fCache.id))
  assert.ok(composites[0]!.dependsOnFactIds.includes(fAsyncExport.id))

  // Composite 2: Request-Parsing -> Concurrent Settlement
  assert.match(composites[1]!.title, /Request-Parsing -> Concurrent Settlement/i)
  assert.ok(composites[1]!.dependsOnFactIds.includes(fParser.id))
  assert.ok(composites[1]!.dependsOnFactIds.includes(fRace.id))

  // Both synthesized composites outline full 3-5 stage sequences and single-script SDK helpers.
  for (const comp of composites) {
    assert.equal(isMultiHopChainStep(comp), true)
    assert.equal(classifyDispatchLane(comp), 'chain')
    assert.equal(chainLaneDispatchRank(comp), 0)
    assert.match(comp.hypothesis, /Stage 1 .* -> .*Stage 2 .* -> .*Stage 3 .* -> Terminal Verification/)
    assert.match(comp.hypothesis, /Verify ALL stages in ONE kovo_verify script/i)
    assert.match(comp.hypothesis, /run clean denied control BEFORE Stage 1/i)
    assert.match(comp.hypothesis, /ctx\.seal_capability/)
    assert.match(comp.hypothesis, /ctx\.hmac_sign\/ctx\.jwt_sign\/ctx\.await_async\/ctx\.prove_race_burst/)
    assert.match(comp.hypothesis, /ctx\.prove_composite/)
    assert.match(comp.hypothesis, /never stop at an intermediate info-disclosure, job creation, cache prime, or token\/link stub/i)
    assert.ok(comp.hypothesis.length <= 1200, `composite hypothesis must stay <= 1200 chars without store truncation (got ${comp.hypothesis.length})`)
  }

  // Round-robin dispatch prioritizes the two synthesized composite workflows ahead of individuals.
  const plan = planRoundRobinDispatch(steps, 3)
  assert.equal(plan.ordered[0]!.id, composites[0]!.id)
  assert.equal(plan.ordered[1]!.id, composites[1]!.id)

  // Idempotency across repeated calls.
  const rerun = convertCodeAuditSuspectsToChainSteps(storage, run, [fCache, fAsyncExport, fParser, fRace], undefined, {
    maxSteps: CODE_AUDIT_WAVE1_MAX_STEPS,
    promoteMultiHop: true,
  })
  assert.equal(rerun.length, 0)
})

test('Q30.3: directory/identity + state-change synthesis and zero contamination / live SDK check', async (t) => {
  const { storage } = makeStore(t)
  const { run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const auditor = storage.makeWorker(run, 'threat_model', asset, 'Source-First Code Audit', 'Audit')

  const fDirectory = storage.addFact(run, auditor, {
    kind: 'code_audit_suspect',
    origin: ORIGIN,
    summary: 'Directory endpoint returns member identifiers and invite metadata across workspaces.',
    data: {
      subkind: 'code_audit_suspect',
      file: 'services/directory/members.ts',
      line: 29,
      routeOrAction: 'GET /api/v1/directory/members',
      sinkKind: 'api_route',
      authCheck: 'member',
      ownershipCheck: 'missing',
      hypothesis: 'Directory lookup exposes foreign workspace member IDs and pending approval records.',
    },
  })
  const fIdentity = storage.addFact(run, auditor, {
    kind: 'code_audit_suspect',
    origin: ORIGIN,
    summary: 'Identity role grant endpoint trusts caller-supplied actor header without approver separation.',
    data: {
      subkind: 'code_audit_suspect',
      file: 'services/identity/roles.ts',
      line: 91,
      routeOrAction: 'POST /api/v1/identity/roles/grant',
      sinkKind: 'auth_config',
      authCheck: 'weak',
      ownershipCheck: 'missing',
      hypothesis: 'Identity service mints elevated role token from leaked workspace identifier.',
    },
  })
  const fStateChange = storage.addFact(run, auditor, {
    kind: 'code_audit_suspect',
    origin: ORIGIN,
    summary: 'State change endpoint approves queued payout without checking creator versus approver.',
    data: {
      subkind: 'code_audit_suspect',
      file: 'services/payouts/approve.ts',
      line: 140,
      routeOrAction: 'POST /api/v1/payouts/:id/approve',
      sinkKind: 'db_query',
      authCheck: 'session',
      ownershipCheck: 'missing',
      hypothesis: 'Elevated token completes unauthorized payout state-change.',
    },
  })

  const steps = convertCodeAuditSuspectsToChainSteps(storage, run, [fDirectory, fIdentity, fStateChange], undefined, {
    maxSteps: CODE_AUDIT_WAVE1_MAX_STEPS,
    promoteMultiHop: true,
  })
  const composites = steps.filter(s => s.title.startsWith('Source audit composite chain ·'))
  assert.equal(composites.length, 1)
  assert.match(composites[0]!.title, /Disclosure -> Auth\/Session -> Privileged Mutation/i)
  assert.match(composites[0]!.hypothesis, /Hop 1 \/ Stage 1 .* -> Hop 2 \/ Stage 2 .* -> Hop 3 \/ Stage 3 .* -> Terminal Verification/)
  assert.ok(composites[0]!.dependsOnFactIds.includes(fDirectory.id))
  assert.ok(composites[0]!.dependsOnFactIds.includes(fIdentity.id))
  assert.ok(composites[0]!.dependsOnFactIds.includes(fStateChange.id))

  // Verify no leased source file introduces nonexistent ctx.race( and zero v8 benchmark contamination.
  for (const relPath of ['src/server/agent-prompts.ts', 'src/server/exec-dispatch.ts', 'src/skills/multihop-chains.md']) {
    const content = readFileSync(resolve(REPO_ROOT, relPath), 'utf8')
    assert.equal(/\bctx\.race\b/.test(content), false, `${relPath} must not reference nonexistent ctx.race`)
  }
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `Unexpected contamination: ${JSON.stringify(scan.hits)}`)
  assert.deepEqual(scan.hits, [])
})
