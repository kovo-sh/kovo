/**
 * v8 Queue #31 Multi-Hop Step Detection & Composite SDK Adoption Regression Tests.
 *
 * Verifies (Docker-free, zero benchmark contamination):
 *  1. `isMultiHopChainStep` (`src/server/exec-dispatch.ts`) and `workerInvestigationPrompt`
 *     (`src/server/agent-prompts.ts`) share the exact same `matchesMultiHopStepSignal` rule and
 *     detect late-wave planner multi-stage steps:
 *     - "Clean-session chain · ..."
 *     - "Compose verified intermediates into one Mode-A causal proof..."
 *     - "Final confirm: ..."
 *     - "Close open proof gap ..."
 *     - "composite chain" / "composite proof" / "causal proof"
 *     - explicit multi-stage arrow sequences (`->` / `→` linking 2+ stages/routes/services)
 *     - multi-fact steps (`dependsOnFactIds.length >= 2`, or `parentFacts.length >= 2` when
 *       `dependsOnFactIds` is omitted on the prompt step)
 *     granting them the scaled 270s (15m) / 300s (30m) wall-clock window and `multiHopDirectives`.
 *  2. Genuine standalone single-route sweeps (0–1 parent facts, no chain/compose/arrow signals,
 *     including bare HTTP status arrows like `200 -> 403` and HTML comments `-->`) stay at the
 *     fast 120s rotation window and omit `multiHopDirectives`.
 *  3. `workerInvestigationPrompt`'s `multiHopDirectives` unmistakably mandates
 *     `ctx.seal_capability(...)` + `ctx.prove_composite(...)` (using `ctx.hmac_sign`,
 *     `ctx.jwt_sign`, `ctx.await_async`, `ctx.prove_race_burst` as intermediate hop primitives
 *     inside the SAME script), forbids substituting standalone single-hop
 *     `prove_access_boundary` / `prove_persisted_mutation` as the final proof, and includes the
 *     1-line call signature reminder.
 *  4. `kovoVerifyHelperGuidance() <= 2048 B`, `kovoVerifyPromptHint() <= 512 B`, and
 *     zero v8 benchmark literals exist in `src/server/**` or `src/skills/**`.
 */
import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { test } from 'node:test'

import {
  KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
  kovoVerifyHelperGuidance,
  kovoVerifyPromptHint,
  matchesMultiHopStepSignal,
  workerInvestigationPrompt,
} from '../src/server/agent-prompts.ts'
import {
  classifyDispatchLane,
  isMultiHopChainStep,
  resolveWorkerSettlementMs,
  resolveWorkerWallClockMs,
  type DispatchLaneStep,
} from '../src/server/exec-dispatch.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'

const REPO_ROOT = resolve(new URL('..', import.meta.url).pathname)
const ORIGIN = 'https://multihop.example.invalid'

type MultiHopDirectivesShape = {
  requiredCompositeProof?: string
  compositeCallSignature?: string
  noPrematureSingleHop?: string
  singleOriginProbeArm?: string
  cryptoAndAsyncHelpers?: string
  singleScriptConsolidation?: string
  stateTransitionControlOrder?: string
}

function makeStep(overrides: Partial<DispatchLaneStep> & { title: string; hypothesis: string }): DispatchLaneStep {
  return {
    id: 'step-q31',
    seq: 1,
    priority: 90,
    category: 'broken-access-control',
    skills: ['bola-idor-race'],
    dependsOnStepIds: [],
    dependsOnFactIds: [],
    sourceOrigins: [ORIGIN],
    ...overrides,
  }
}

test('Q31.1: late-wave planner multi-stage steps match isMultiHopChainStep, get 270s-300s wall-clock, and receive multiHopDirectives', () => {
  const plannerCases: Array<{ label: string; step: DispatchLaneStep }> = [
    {
      label: 'Clean-session chain title',
      step: makeStep({
        title: 'Clean-session chain · Cross-tenant webhook relay approval',
        hypothesis: 'Replay all stages from a single low-privilege session.',
      }),
    },
    {
      label: 'Compose verified intermediates into Mode-A causal proof',
      step: makeStep({
        title: 'Compose verified intermediates into one Mode-A causal proof for export service',
        hypothesis: 'Combine previously confirmed token disclosure and export readback.',
      }),
    },
    {
      label: 'Final confirm title',
      step: makeStep({
        title: 'Final confirm: cross-org ledger state mutation',
        hypothesis: 'Run full clean-session end-to-end confirmation.',
      }),
    },
    {
      label: 'Close open proof gap title',
      step: makeStep({
        title: 'Close open proof gap on internal signing relay',
        hypothesis: 'Link leaked signing secret to downstream privileged mutation.',
      }),
    },
    {
      label: 'Composite chain / composite proof in hypothesis',
      step: makeStep({
        title: 'Verify billing service escalation',
        hypothesis: 'Build a composite proof binding cache prime and async download.',
      }),
    },
    {
      label: 'Composite chain title',
      step: makeStep({
        title: 'Composite chain verification for invite pivot',
        hypothesis: 'Execute cross-service verification script.',
      }),
    },
    {
      label: 'Causal proof in hypothesis',
      step: makeStep({
        title: 'Verify cross-service session forgery',
        hypothesis: 'Emit a Mode-A causal proof covering token extraction and admin read.',
      }),
    },
    {
      label: 'ASCII arrow linking routes',
      step: makeStep({
        title: 'Cross-route escalation verification',
        hypothesis: 'Pivot GET /api/v1/cache/prime -> POST /api/v1/exports -> GET /api/v1/downloads/latest.',
      }),
    },
    {
      label: 'Unicode arrow linking stages/services',
      step: makeStep({
        title: 'Cache prime → Async export download',
        hypothesis: 'Verify cross-tenant readback across services.',
      }),
    },
    {
      label: 'ASCII arrow linking named services',
      step: makeStep({
        title: 'Verify gateway to settlement flow',
        hypothesis: 'edge proxy -> internal signer -> settlement worker',
      }),
    },
    {
      label: 'dependsOnFactIds.length >= 2',
      step: makeStep({
        title: 'Verify linked findings across services',
        hypothesis: 'Correlate upstream findings into one verification script.',
        dependsOnFactIds: ['fact-1', 'fact-2'],
      }),
    },
  ]

  for (const { label, step } of plannerCases) {
    assert.equal(matchesMultiHopStepSignal(step), true, `${label}: matchesMultiHopStepSignal must be true`)
    assert.equal(isMultiHopChainStep(step), true, `${label}: isMultiHopChainStep must be true`)
    assert.equal(classifyDispatchLane(step), 'chain', `${label}: must route to chain lane`)
    assert.equal(resolveWorkerWallClockMs(step, 900_000), 270_000, `${label}: 15m run must get 270s wall-clock`)
    assert.equal(resolveWorkerWallClockMs(step, 1_800_000), 300_000, `${label}: 30m run must get 300s wall-clock`)
    assert.equal(resolveWorkerSettlementMs(270_000, true), 245_000)
    assert.equal(resolveWorkerSettlementMs(300_000, true), 275_000)

    const parsed = JSON.parse(workerInvestigationPrompt({
      goal: 'Verify end-to-end cross-service boundary',
      step: {
        id: step.id,
        title: step.title,
        hypothesis: step.hypothesis ?? '',
        category: step.category ?? 'broken-access-control',
        skills: step.skills ?? [],
        dependsOnStepIds: step.dependsOnStepIds,
        dependsOnFactIds: step.dependsOnFactIds,
      },
      origins: [ORIGIN],
      capabilityTier: 2,
      maxTurns: 12,
    })) as { multiHopDirectives?: MultiHopDirectivesShape }

    assert.ok(parsed.multiHopDirectives, `${label}: workerInvestigationPrompt must emit multiHopDirectives`)
  }
})

test('Q31.2: workerInvestigationPrompt aligns with exec-worker-runner when parentFacts.length >= 2 without step.dependsOnFactIds', () => {
  const promptWith2Facts = JSON.parse(workerInvestigationPrompt({
    goal: 'Correlate two verified leads',
    step: {
      id: 'step-parent-facts-2',
      title: 'Verify cross-service impact',
      hypothesis: 'Exercise correlated endpoints in one verification run.',
      category: 'broken-access-control',
      skills: ['bola-idor-race'],
    },
    origins: [ORIGIN],
    capabilityTier: 2,
    maxTurns: 12,
    parentFacts: [
      { id: 'f-1', kind: 'code_audit_suspect', origin: ORIGIN, summary: 'Suspect 1' },
      { id: 'f-2', kind: 'code_audit_suspect', origin: ORIGIN, summary: 'Suspect 2' },
    ],
  })) as { multiHopDirectives?: MultiHopDirectivesShape }
  assert.ok(promptWith2Facts.multiHopDirectives, '2+ parentFacts must trigger multiHopDirectives')

  const promptWith1Fact = JSON.parse(workerInvestigationPrompt({
    goal: 'Check single route',
    step: {
      id: 'step-parent-facts-1',
      title: 'Single-route access sweep',
      hypothesis: 'Check GET /api/v1/items/:id authorization matrix.',
      category: 'broken-access-control',
      skills: ['bola-idor-race'],
    },
    origins: [ORIGIN],
    capabilityTier: 2,
    maxTurns: 8,
    parentFacts: [
      { id: 'f-1', kind: 'endpoint', origin: ORIGIN, summary: 'Single endpoint discovery' },
    ],
  })) as { multiHopDirectives?: unknown }
  assert.equal(promptWith1Fact.multiHopDirectives, undefined, 'single parentFact on single-route step must omit multiHopDirectives')
})

test('Q31.3: genuine standalone single-route sweeps stay at 120s rotation window and omit multiHopDirectives', () => {
  const singleRouteCases: Array<{ label: string; step: DispatchLaneStep; expectedWallClockMs?: number }> = [
    {
      label: 'Single-route access sweep',
      step: makeStep({
        title: 'Single-route access sweep',
        hypothesis: 'Verify GET /api/v1/items/:id authorization matrix.',
        skills: ['bola-bfla'],
      }),
    },
    {
      label: 'Single-endpoint header check',
      step: makeStep({
        title: 'Single-endpoint header check',
        hypothesis: 'Check response policy on /api/v1/health.',
        category: 'misconfig-exposure',
        skills: ['false-positive-elimination'],
      }),
    },
    {
      label: 'Single-route SQLi differential',
      step: makeStep({
        title: 'SQLi check on /api/v1/search',
        hypothesis: 'Verify boolean differential on query parameter.',
        category: 'injection-input',
        skills: ['injection-sqli-nosqli'],
        dependsOnFactIds: ['fact-only-one'],
      }),
      // Citing 1 upstream fact classifies as multi_step (20 turns, not multi_hop_chain);
      // R2-19 (2399101) scales multi_step rotation to 20 * ceil(120s / 18) = 133_340ms
      // to keep seconds-per-turn non-decreasing without escalating to the 270s-300s chain window.
      expectedWallClockMs: 133_340,
    },
    {
      label: 'Bare HTTP status code arrow (200 -> 403)',
      step: makeStep({
        title: 'Verify access control on /api/v1/orders',
        hypothesis: 'Confirm unauthenticated caller gets HTTP 200 -> 403 rejection.',
        skills: ['bola-bfla'],
      }),
    },
    {
      label: 'HTML comment arrow (-->)',
      step: makeStep({
        title: 'Inspect template reflection on /profile',
        hypothesis: 'Check whether <!-- marker --> is stripped from HTML output.',
        category: 'client-side',
        skills: ['xss-csrf-cors'],
      }),
    },
  ]

  for (const { label, step, expectedWallClockMs = 120_000 } of singleRouteCases) {
    assert.equal(matchesMultiHopStepSignal(step), false, `${label}: matchesMultiHopStepSignal must be false`)
    assert.equal(isMultiHopChainStep(step), false, `${label}: isMultiHopChainStep must be false`)
    assert.equal(resolveWorkerWallClockMs(step, 900_000), expectedWallClockMs, `${label}: 15m run must stay at ${expectedWallClockMs}ms`)
    assert.equal(resolveWorkerWallClockMs(step, 1_800_000), expectedWallClockMs, `${label}: 30m run must stay at ${expectedWallClockMs}ms`)
    assert.equal(resolveWorkerWallClockMs(step, undefined), expectedWallClockMs, `${label}: default run must stay at ${expectedWallClockMs}ms`)

    const parsed = JSON.parse(workerInvestigationPrompt({
      goal: 'Single route verification',
      step: {
        id: step.id,
        title: step.title,
        hypothesis: step.hypothesis ?? '',
        category: step.category ?? 'broken-access-control',
        skills: step.skills ?? [],
        dependsOnStepIds: step.dependsOnStepIds,
        dependsOnFactIds: step.dependsOnFactIds,
      },
      origins: [ORIGIN],
      capabilityTier: 2,
      maxTurns: 8,
    })) as { multiHopDirectives?: unknown }

    assert.equal(parsed.multiHopDirectives, undefined, `${label}: single-route sweep must omit multiHopDirectives`)
  }
})

test('Q31.4: multiHopDirectives unmistakably mandates ctx.seal_capability + ctx.prove_composite and includes compact signature reminder', () => {
  const parsed = JSON.parse(workerInvestigationPrompt({
    goal: 'Verify end-to-end multi-stage chain',
    step: {
      id: 'step-q31-sdk',
      title: 'Clean-session chain · Cross-service escalation',
      hypothesis: 'Stage 1 -> Stage 2 -> Stage 3 -> Terminal readback.',
      category: 'broken-access-control',
      skills: ['bola-idor-race'],
    },
    origins: [ORIGIN],
    capabilityTier: 2,
    maxTurns: 16,
  })) as { multiHopDirectives?: MultiHopDirectivesShape }

  const directives = parsed.multiHopDirectives
  assert.ok(directives, 'multiHopDirectives must be present')

  // Unmistakable composite verification contract forbidding single-hop substitution.
  assert.ok(directives.requiredCompositeProof, 'requiredCompositeProof directive must be present')
  assert.match(directives.requiredCompositeProof!, /MUST verify the end-to-end causal chain with ctx\.seal_capability\(\.\.\.\) \+ ctx\.prove_composite\(\.\.\.\)/)
  assert.match(directives.requiredCompositeProof!, /ctx\.hmac_sign \/ ctx\.jwt_sign \/ ctx\.await_async \/ ctx\.prove_race_burst/)
  assert.match(directives.requiredCompositeProof!, /do NOT substitute a standalone single-hop prove_access_boundary \/ prove_persisted_mutation call as your final proof/i)

  // Compact 1-line call signature reminder.
  assert.ok(directives.compositeCallSignature, 'compositeCallSignature must be present')
  assert.equal(directives.compositeCallSignature!.includes('\n'), false, 'compositeCallSignature must be a single line')
  assert.equal(
    directives.compositeCallSignature,
    'ctx.seal_capability({ exchangeId, slot, jsonPath, kind }) -> ctx.hmac_sign/jwt_sign/await_async -> ctx.prove_composite({ chainId, terminalVulnClass, replayMode: "fresh_clean_replay", hops, causalEdges, terminalImpact })',
  )

  // Existing directives remain intact.
  assert.ok(directives.noPrematureSingleHop)
  assert.ok(directives.singleOriginProbeArm)
  assert.ok(directives.cryptoAndAsyncHelpers)
  assert.ok(directives.singleScriptConsolidation)
  assert.ok(directives.stateTransitionControlOrder)
})

test('Q31.5: prompt guidance stays within <= 2048 B budget and source tree has zero v8 contamination', () => {
  const guidanceBytes = Buffer.byteLength(kovoVerifyHelperGuidance(), 'utf8')
  const hintBytes = Buffer.byteLength(kovoVerifyPromptHint(), 'utf8')
  assert.ok(
    guidanceBytes <= KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
    `kovoVerifyHelperGuidance() is ${guidanceBytes} B (> ${KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES} B)`,
  )
  assert.ok(hintBytes <= 512, `kovoVerifyPromptHint() is ${hintBytes} B (> 512 B)`)

  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `v8 contamination detected: ${JSON.stringify(scan.hits)}`)
  assert.equal(scan.hits.length, 0)
})
