/**
 * v8 M2 Stream C — Multi-Hop Briefs, Grey-Box Wiring & Prompt/Skill Recipe Trap Fixes.
 *
 * Pure behavioral regression suite (0 source-text regex assertions):
 *  1. Grey-Box Wave-1 `class_scan` / `business_logic` briefs receive the compact Mode-A
 *     `multiHopProofContract` whenever `codeSlice` (>= 2 hops or >= 2 mounts), multi-origin
 *     (`publicOrigins.length >= 2`), or CapabilityLedger sealed capabilities (`sealedCapabilityCount > 0`)
 *     are present, while single-origin single-hop briefs stay compact without it.
 *  2. `ExecReconPlanner.assignmentBriefForStep` wires multi-origin run candidates and live
 *     `CapabilityLedger` sealed capabilities into `buildAssignmentBrief` automatically.
 *  3. Recipe traps are eliminated across full/compact `buildMultiHopProofContract`, helper patterns,
 *     and `loadSkill('multihop-chains')`:
 *     - No hardcoded `terminalVulnClass: "dual_tenant_abac"` (explicit impact-class matching guidance).
 *     - No hardcoded benchmark/persona handles (`member_b`, `dual_member`, etc.); explicit SAME-actor
 *       ablation control requirement matching `toHop`.
 *     - All 4 `causalEdges.kind` enum literals present (`value_binding`, `derived_crypto_binding`,
 *       `state_transition_binding`, `async_pivot_binding`).
 *     - Single-script Mode-A rule (explore with `kovo_http`, never seal-only `kovo_verify`, run
 *       Hop 1..N + `ctx.chain(...).prove()` in ONE script) and low-privilege / dual-tenant persona rule.
 *  4. Zero v8 benchmark contamination across `src/server/**` and `src/skills/**`.
 */
import assert from 'node:assert/strict'
import { dirname, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  ASSIGNMENT_BRIEF_MAX_BYTES,
  ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
  MULTIHOP_AWAIT_ASYNC_PATTERN,
  MULTIHOP_MODE_A_TS_RECIPE,
  buildAssignmentBriefPacket,
  buildMultiHopProofContract,
  isMultiHopBriefInput,
  type AssignmentBriefMultiHopContract,
} from '../src/server/assignment-brief.ts'
import { Execution } from '../src/server/execution.ts'
import type { CodeDataflowSlice } from '../src/server/program-graph.ts'
import {
  MULTIHOP_CHAINS_SKILL,
  clearSkillsCache,
  loadSkill,
  selectPreInjectionSkills,
} from '../src/server/skills.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function sampleCodeSlice(overrides: Partial<CodeDataflowSlice> = {}): CodeDataflowSlice {
  return {
    route: 'POST /api/v1/transfers',
    mounts: ['/api/v1'],
    methods: ['POST'],
    input: { body: ['amount', 'targetId'] },
    auth: 'guarded',
    guards: ['requireSession'],
    root: 'services/ledger/src/',
    hops: [
      { at: 'routes.ts:18', kind: 'route' },
      { at: 'services/transfer.ts:44' },
    ],
    sink: { at: 'services/transfer.ts:44', kind: 'db_query' },
    ...overrides,
  }
}

test('isMultiHopBriefInput unblocks Grey-Box class_scan/business_logic via codeSlice, multi-origin, or sealed capabilities', () => {
  // Single-origin single-hop class_scan stays non-multi-hop and omits multiHopProofContract.
  assert.equal(isMultiHopBriefInput({ missionKind: 'class_scan' }), false)
  assert.equal(
    isMultiHopBriefInput({
      missionKind: 'class_scan',
      publicOrigins: ['https://svc-a.example.test'],
      sealedCapabilityCount: 0,
      codeSlice: sampleCodeSlice({ hops: [{ at: 'routes.ts:10', kind: 'route' }] }),
    }),
    false,
  )
  const singlePacket = buildAssignmentBriefPacket({
    missionKind: 'class_scan',
    origin: 'https://svc-a.example.test',
    routes: [{ method: 'GET', path: '/api/items', riskScore: 50 }],
  })
  assert.ok(singlePacket.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES)
  assert.equal((JSON.parse(singlePacket.text) as { multiHopProofContract?: unknown }).multiHopProofContract, undefined)

  // Existing explicit multi-hop missions stay true.
  for (const missionKind of ['chain_step_2', 'multihop_chain', 'second_order'] as const) {
    assert.equal(isMultiHopBriefInput({ missionKind }), true)
  }

  // Trigger 1: Grey-Box codeSlice with >= 2 hops or >= 2 mounts.
  assert.equal(isMultiHopBriefInput({ missionKind: 'class_scan', codeSlice: sampleCodeSlice() }), true)
  assert.equal(
    isMultiHopBriefInput({
      missionKind: 'business_logic',
      codeSlice: sampleCodeSlice({ hops: [{ at: 'r.ts:1', kind: 'route' }], mounts: ['/v1', '/internal'] }),
    }),
    true,
  )

  // Trigger 2: Multi-origin / multi-service investigation (>= 2 origins).
  assert.equal(
    isMultiHopBriefInput({
      missionKind: 'class_scan',
      publicOrigins: ['https://svc-a.example.test', 'https://svc-b.example.test'],
    }),
    true,
  )

  // Trigger 3: Run already has sealed capabilities in CapabilityLedger.
  assert.equal(
    isMultiHopBriefInput({
      missionKind: 'business_logic',
      sealedCapabilityCount: 1,
    }),
    true,
  )

  // Each Grey-Box trigger delivers compact multiHopProofContract within the 4 KB cap.
  const cases = [
    {
      label: 'class_scan + codeSlice',
      input: {
        missionKind: 'class_scan' as const,
        origin: 'https://svc-a.example.test',
        routes: [{ method: 'POST', path: '/api/v1/transfers', riskScore: 85 }],
        codeSlice: sampleCodeSlice(),
      },
      maxCap: ASSIGNMENT_BRIEF_MAX_BYTES,
    },
    {
      label: 'business_logic + multi-origin',
      input: {
        missionKind: 'business_logic' as const,
        origin: 'https://svc-a.example.test',
        publicOrigins: ['https://svc-a.example.test', 'https://svc-b.example.test'],
        routes: [{ method: 'POST', path: '/api/v1/exports', riskScore: 90 }],
      },
      maxCap: ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
    },
    {
      label: 'class_scan + sealedCapabilityCount',
      input: {
        missionKind: 'class_scan' as const,
        origin: 'https://svc-a.example.test',
        sealedCapabilityCount: 2,
        routes: [{ method: 'GET', path: '/api/v1/reports', riskScore: 80 }],
      },
      maxCap: ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
    },
  ]

  for (const c of cases) {
    const packet = buildAssignmentBriefPacket(c.input)
    assert.ok(packet.bytes <= c.maxCap, `${c.label}: ${packet.bytes} B exceeded ${c.maxCap} B`)
    const parsed = JSON.parse(packet.text) as { multiHopProofContract?: AssignmentBriefMultiHopContract }
    assert.ok(parsed.multiHopProofContract, `${c.label} must include multiHopProofContract`)
    assert.ok(parsed.multiHopProofContract.modeATsRecipe.length > 40)
    assert.ok(parsed.multiHopProofContract.continueChainRule.length > 20)
    assert.ok(parsed.multiHopProofContract.hardenedTwinRule.includes('invariant_enforced_hardened'))
  }
})

test('ExecReconPlanner.assignmentBriefForStep wires multi-origin candidates and CapabilityLedger counts into Grey-Box briefs', async t => {
  const { storage } = makeStore(t, 'kovo-v8-m2-brief-wire-')
  const originA = 'https://gateway.example.test'
  const originB = 'https://worker-api.example.test'
  const setup = await setupApprovedRun(storage, { seeds: [originA, originB], tier: 3, budgetRequests: 900 })
  storage.updateRun(setup.runId, { phase: 'investigation', status: 'running' })
  const execution = new Execution(storage)
  t.after(() => execution.stop())

  const internals = execution as unknown as Record<string, (...args: unknown[]) => unknown>
  const briefMultiOrigin = internals.assignmentBriefForStep({
    run: storage.run(setup.runId),
    step: {
      id: 'step-gb-1',
      title: 'Wave-1 class scan on gateway',
      hypothesis: 'Audit authorization invariants across gateway endpoints.',
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

  assert.ok(briefMultiOrigin, 'multi-origin Wave-1 brief must render')
  const parsedMulti = JSON.parse(briefMultiOrigin!) as {
    mission: string
    multiHopProofContract?: AssignmentBriefMultiHopContract
  }
  assert.equal(parsedMulti.mission, 'class_scan')
  assert.ok(parsedMulti.multiHopProofContract, 'multi-origin Wave-1 class_scan brief must include multiHopProofContract')

  // Single-origin run with a sealed capability in CapabilityLedger also receives multiHopProofContract.
  const singleSetup = await setupApprovedRun(storage, { seeds: [originA], tier: 3, budgetRequests: 900 })
  storage.updateRun(singleSetup.runId, { phase: 'investigation', status: 'running' })
  storage.capabilityLedger(singleSetup.runId).addCapability({
    capId: 'cap:hop_1:session_tok',
    kind: 'scoped_token',
    provenance: 'derived_hop',
    surface: 'http',
    tenantScope: 'org_b',
    actorPersona: 'actor_low',
    serviceOrigin: originA,
    artifactDigest: 'a'.repeat(64),
    parentHopReceiptIds: ['ex-hop-1'],
  })

  const briefWithCap = internals.assignmentBriefForStep({
    run: storage.run(singleSetup.runId),
    step: {
      id: 'step-gb-cap',
      title: 'Wave-1 business logic audit',
      hypothesis: 'Inspect state machine transitions on single origin.',
      category: 'business-logic',
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

  assert.ok(briefWithCap, 'ledger-backed Wave-1 brief must render')
  const parsedCap = JSON.parse(briefWithCap!) as { multiHopProofContract?: AssignmentBriefMultiHopContract }
  assert.ok(parsedCap.multiHopProofContract, 'run with sealed capabilities must include multiHopProofContract')
})

test('Mode-A brief contracts and multihop-chains playbook eliminate dual_tenant_abac/member_b traps and teach all 4 edge kinds', () => {
  const full = buildMultiHopProofContract(false, {
    missionKind: 'multihop_chain',
    origin: 'https://svc.example.test',
    routes: [{ method: 'POST', path: '/api/exports/jobs', riskScore: 90 }],
  })
  const compact = buildMultiHopProofContract(true, {
    missionKind: 'class_scan',
    origin: 'https://svc.example.test',
    routes: [{ method: 'POST', path: '/api/exports/jobs', riskScore: 90 }],
    codeSlice: sampleCodeSlice(),
  })

  clearSkillsCache()
  const skill = loadSkill(MULTIHOP_CHAINS_SKILL)
  assert.ok(skill, 'multihop-chains skill must load')
  const playbook = skill!.content

  // Trap 1: Never hardcode terminalVulnClass: "dual_tenant_abac" or 'dual_tenant_abac' in recipes.
  assert.equal(MULTIHOP_MODE_A_TS_RECIPE.includes('terminalVulnClass: "dual_tenant_abac"'), false)
  assert.equal(compact.modeATsRecipe.includes('terminalVulnClass:"dual_tenant_abac"'), false)
  assert.equal(playbook.includes("terminalVulnClass: 'dual_tenant_abac'"), false)
  assert.equal(playbook.includes('terminalVulnClass: "dual_tenant_abac"'), false)
  for (const impactClass of [
    'broken_access_control',
    'privilege_escalation',
    'stale_privilege_use',
    'cross_tenant_export',
    'ledger_overcredit',
    'forged_settlement',
  ]) {
    assert.ok(full.modeATsRecipe.includes(impactClass), `full recipe missing impact class ${impactClass}`)
    assert.ok(compact.modeATsRecipe.includes(impactClass), `compact recipe missing impact class ${impactClass}`)
    assert.ok(playbook.includes(impactClass), `multihop-chains.md missing impact class ${impactClass}`)
  }

  // Trap 2: Zero hardcoded benchmark/real persona handles; ablation must use SAME actor as toHop.
  const combinedBriefText = [
    JSON.stringify(full),
    JSON.stringify(compact),
    MULTIHOP_AWAIT_ASYNC_PATTERN,
    playbook,
  ].join('\n')
  for (const forbidden of ['member_b', 'member_a', 'dual_member', 'revoked_or_demoted']) {
    assert.equal(combinedBriefText.includes(forbidden), false, `hardcoded persona "${forbidden}" leaked into brief/playbook`)
  }
  assert.ok(full.attackerOriginRule.includes('SAME actor'))
  assert.ok(compact.attackerOriginRule.includes('SAME actor'))
  assert.ok(playbook.includes('SAME actor'))

  // Trap 3: All 4 valid causalEdges.kind literals appear in full recipe, compact recipe, and playbook.
  for (const edgeKind of [
    'value_binding',
    'derived_crypto_binding',
    'state_transition_binding',
    'async_pivot_binding',
  ]) {
    assert.ok(full.modeATsRecipe.includes(edgeKind), `full recipe missing causalEdges.kind ${edgeKind}`)
    assert.ok(compact.modeATsRecipe.includes(edgeKind), `compact recipe missing causalEdges.kind ${edgeKind}`)
    assert.ok(playbook.includes(edgeKind), `multihop-chains.md missing causalEdges.kind ${edgeKind}`)
  }

  // Trap 4: Single-script Mode-A rule + dual-tenant persona scope rule.
  assert.ok(full.continueChainRule.includes('kovo_http'))
  assert.ok(compact.continueChainRule.includes('kovo_http'))
  assert.ok(full.continueChainRule.includes('ctx.chain('))
  assert.ok(compact.continueChainRule.includes('ctx.chain('))
  assert.ok(full.attackerOriginRule.includes('non-admin tenant'))
  assert.ok(compact.attackerOriginRule.includes('non-admin tenant'))
  assert.ok(playbook.includes('kovo_http'))
  assert.ok(playbook.includes('non-admin tenant'))

  // Pre-injection excerpt stays strictly <= 1200 chars and includes key contract items.
  const preInjected = selectPreInjectionSkills({ lane: 'chain', limit: 2 })
  const mh = preInjected.find(s => s.name === MULTIHOP_CHAINS_SKILL)
  assert.ok(mh)
  assert.ok(mh!.excerpt.length <= 1200)
  assert.ok(mh!.excerpt.includes('invariant_enforced_hardened'))
  assert.ok(mh!.excerpt.includes('kovo_http'))

  // Zero v8 benchmark contamination across src/server/ and src/skills/.
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `v8 contamination hits: ${JSON.stringify(scan.hits)}`)
})
