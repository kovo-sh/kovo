/**
 * v8 Stream A — Multi-Hop Specialist Playbook & Hop-Checkpoint Briefs.
 *
 * Verifies:
 *  1. `multihop-chains` skill resolves cleanly via `skills.ts` (canonical slug, tags, search, aliases)
 *     and documents all v8 multi-hop verification primitives + hardened-twin zero-FP discipline.
 *  2. Zero benchmark literals or raw secrets exist in `src/skills/multihop-chains.md`,
 *     `src/server/skills.ts`, or `src/server/assignment-brief.ts`.
 *  3. Profile pre-injection automatically injects `multihop-chains` for multi-hop chain assignments
 *     while preserving every existing M1.4 specialist skill slug & single-hop ranking invariant.
 *  4. `assignment-brief.ts` embeds bounded v8 `hopCheckpoint` briefs (`<= 2 KB`, opaque `cap:...`
 *     handles, verified parent hops, next-hop pivot target, `doNotRediscover: true`) while staying
 *     within the `<= 4 KB` total brief budget and scrubbing all raw secret patterns.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { test } from 'node:test'

import { SPECIALIST_PROFILES } from '../src/server/agent-session.ts'
import {
  ASSIGNMENT_BRIEF_HOP_CHECKPOINT_MAX_BYTES,
  ASSIGNMENT_BRIEF_MAX_BYTES,
  ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
  HOP_CHECKPOINT_SCHEMA_V1,
  buildAssignmentBriefPacket,
  fitHopCheckpointForBrief,
  measureAssignmentBriefBytes,
  sanitizeCapabilityHandle,
  type AssignmentBriefHopCheckpoint,
  type RenderedHopCheckpoint,
} from '../src/server/assignment-brief.ts'
import {
  buildHopCheckpointBrief,
  type FrontierBranch,
} from '../src/server/frontier-scheduler.ts'
import type { CodeDataflowSlice } from '../src/server/program-graph.ts'
import {
  MULTIHOP_CHAINS_SKILL,
  clearSkillsCache,
  isMultiHopChainAssignment,
  listSkills,
  loadSkill,
  resolveSkillName,
  resolveSkillsForProfile,
  searchSkills,
  selectPreInjectionSkills,
  skillsByTag,
} from '../src/server/skills.ts'

const REPO_ROOT = resolve(new URL('..', import.meta.url).pathname)

// ============================================================================
// 1. Skill resolution, playbook completeness & zero benchmark leakage
// ============================================================================

test('multihop-chains skill resolves via skills.ts and covers all v8 verification primitives', () => {
  clearSkillsCache()
  const skill = loadSkill(MULTIHOP_CHAINS_SKILL)
  assert.ok(skill, 'multihop-chains playbook must load')
  assert.equal(skill.name, 'multihop-chains')
  assert.ok(skill.title.length > 10)
  assert.ok(skill.summary.length > 40)
  assert.ok(skill.tags.includes('multihop'))
  assert.ok(skill.tags.includes('hop-checkpoint'))

  assert.ok(listSkills().some(s => s.name === 'multihop-chains'))
  assert.ok(skillsByTag('multihop').some(s => s.name === 'multihop-chains'))
  assert.ok(searchSkills('CompositeProofReceipt').some(s => s.name === 'multihop-chains'))

  // Aliases normalize cleanly to multihop-chains.
  assert.equal(resolveSkillName('multi-hop'), 'multihop-chains')
  assert.equal(resolveSkillName('hop-checkpoint'), 'multihop-chains')
  assert.equal(resolveSkillName('composite-receipt'), 'multihop-chains')
  assert.equal(loadSkill('multi-hop')?.name, 'multihop-chains')

  // Required v8 defensive verification primitives and zero-FP hardened-twin contract.
  for (const token of [
    'ctx.seal_capability',
    'cap:hop_',
    'ctx.hmac_sign',
    'ctx.jwt_sign',
    'derivedFromCapabilityId',
    'ctx.await_async',
    'ctx.prove_composite',
    'CompositeProofReceipt',
    'value_binding',
    'derived_crypto_binding',
    'state_transition_binding',
    'ablationExchangeIds',
    'async_pivot_binding',
    'Attacker-Origin Provenance',
    'capability_only',
    'CWE-200',
    'record_coverage',
    'doNotRediscover',
  ]) {
    assert.ok(skill.content.includes(token), `multihop-chains.md must teach ${token}`)
  }
})

test('zero benchmark literals or raw secrets exist in multihop-chains.md, skills.ts, or assignment-brief.ts', () => {
  const forbiddenPatterns: RegExp[] = [
    new RegExp(['pay', 'grid'].join(''), 'i'),
    new RegExp(['ship', 'forge'].join(''), 'i'),
    new RegExp(['nexus', 'iam'].join(''), 'i'),
    new RegExp(['connect', 'hub'].join(''), 'i'),
    /\b(?:PG|SF|NX|CH)-[CD]\d+\b/,
    new RegExp(['vault', '\\.internal'].join(''), 'i'),
    new RegExp(['registry', '\\.internal'].join(''), 'i'),
    new RegExp(['billing', '\\.internal'].join(''), 'i'),
    new RegExp(['mh_', 'fake_'].join(''), 'i'),
  ]

  const files = [
    'src/skills/multihop-chains.md',
    'src/server/skills.ts',
    'src/server/assignment-brief.ts',
  ]
  for (const rel of files) {
    const content = readFileSync(resolve(REPO_ROOT, rel), 'utf8')
    for (const pattern of forbiddenPatterns) {
      assert.equal(
        pattern.test(content),
        false,
        `Forbidden benchmark pattern ${pattern} leaked into ${rel}`,
      )
    }
  }

  // Playbook itself must not embed raw JWTs or key-shaped secrets.
  const playbook = readFileSync(resolve(REPO_ROOT, 'src/skills/multihop-chains.md'), 'utf8')
  assert.equal(/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/.test(playbook), false)
  assert.equal(/\b(?:sk_live|ghp|sk-or-v1)[-_][A-Za-z0-9_-]{8,}/.test(playbook), false)
})

// ============================================================================
// 2. Multi-hop pre-injection & M1.4 specialist skill invariants
// ============================================================================

test('selectPreInjectionSkills automatically injects multihop-chains on multi-hop assignments while preserving domain playbooks', () => {
  const bolaSkills = SPECIALIST_PROFILES['bola-bfla-specialist'].skills
  const authSkills = SPECIALIST_PROFILES['auth-session-oauth-specialist'].skills

  // Explicit flags: multiHop / hasHopCheckpoint / hopDepth >= 2 / missionKind.
  for (const opts of [
    { profileSkills: bolaSkills, multiHop: true },
    { profileSkills: bolaSkills, hasHopCheckpoint: true },
    { profileSkills: authSkills, hopDepth: 3 },
    { profileSkills: authSkills, missionKind: 'chain_step_2' },
    { profileSkills: bolaSkills, missionKind: 'multihop_chain' },
    {
      profileSkills: authSkills,
      title: 'Hop 3 pivot: derive scoped signature via cap:hop_2:signing_salt',
      hypothesis: 'Verify derived_crypto_binding and submit CompositeProofReceipt.',
    },
  ]) {
    assert.equal(isMultiHopChainAssignment(opts), true)
    const selected = selectPreInjectionSkills({ ...opts, limit: 2 })
    assert.equal(selected.length, 2)
    assert.ok(
      selected.some(s => s.name === 'multihop-chains'),
      `expected multihop-chains in pre-injected skills for ${JSON.stringify(opts)}`,
    )
    assert.ok(
      selected.some(s => s.name !== 'multihop-chains'),
      'top domain-specific skill is preserved alongside multihop-chains when limit=2',
    )
    const mh = selected.find(s => s.name === 'multihop-chains')!
    assert.ok(mh.excerpt.length > 0 && mh.excerpt.length <= 1200)
    assert.ok(mh.excerpt.includes('ctx.seal_capability'), '1200-char excerpt includes capability custody contract')
    assert.ok(mh.excerpt.includes('CompositeProofReceipt'), '1200-char excerpt includes CompositeProofReceipt DAG guidance')
  }

  // Even when domain skills score very high from techTags + sinkKind, multi-hop guarantees inclusion.
  const highDomain = selectPreInjectionSkills({
    profileSkills: SPECIALIST_PROFILES['client-browser-dom-specialist'].skills,
    techTags: ['dom', 'postmessage', 'client-side', 'xss', 'cors', 'csrf'],
    sinkKind: 'postmessage_iframe',
    hasHopCheckpoint: true,
    limit: 2,
  })
  assert.equal(highDomain.length, 2)
  assert.ok(highDomain.some(s => s.name === 'multihop-chains'))

  // resolveSkillsForProfile appends multihop-chains only when multiHop=true without mutating profile.
  const baseCount = bolaSkills.length
  const singleProfile = resolveSkillsForProfile(bolaSkills, { multiHop: false })
  const multiProfile = resolveSkillsForProfile(bolaSkills, { multiHop: true })
  assert.equal(bolaSkills.length, baseCount)
  assert.equal(singleProfile.includes('multihop-chains'), false)
  assert.equal(multiProfile.includes('multihop-chains'), true)
  assert.equal(new Set(multiProfile).size, multiProfile.length)
})

test('M1.4 skill invariants and single-hop pre-injection rankings remain intact', () => {
  const known = new Set(listSkills().map(s => s.name))
  for (const [profileId, cfg] of Object.entries(SPECIALIST_PROFILES)) {
    for (const slug of cfg.skills) {
      assert.ok(known.has(slug), `M1.4 regression: missing skill ${profileId}:${slug}`)
    }
  }

  // Exact M1.4 single-hop cache-deception check must not spuriously inject multihop-chains.
  const cacheInput = {
    profileSkills: SPECIALIST_PROFILES['protocol-cache-edge-specialist'].skills,
    techTags: ['cdn'],
    sinkKind: 'redirect',
    title: 'Cache deception on authenticated route',
  }
  assert.equal(isMultiHopChainAssignment(cacheInput), false)
  const cacheSkills = selectPreInjectionSkills(cacheInput)
  assert.ok(cacheSkills.length >= 1 && cacheSkills.length <= 2)
  assert.ok(cacheSkills.some(s => s.name === 'cache-smuggling-desync'))
  assert.equal(cacheSkills.some(s => s.name === 'multihop-chains'), false)

  // Generic single-hop det_lead prose mentioning bare "chain" stays single-hop.
  assert.equal(
    isMultiHopChainAssignment({
      title: 'det_lead upgrade · authz_matrix PATCH /v3/admin/users/:id',
      hypothesis: 'Reproduce it and chain it into a higher-impact finding.',
      category: 'broken-access-control',
      profileSkills: SPECIALIST_PROFILES['bola-bfla-specialist'].skills,
    }),
    false,
  )
})

// ============================================================================
// 3. Bounded hopCheckpoint embedding & secret scrubbing in assignment-brief.ts
// ============================================================================

function sampleFrontierBranch(): FrontierBranch {
  return {
    branchKey: 'branch-dual-org-export',
    depth: 2,
    verifiedHops: [
      {
        hopIndex: 1,
        hopReceiptId: 'hop-rcpt-1',
        capabilityId: 'cap:hop_1:export_handle',
        kind: 'state_handle',
        surface: 'http',
        serviceOrigin: 'https://api.example.test',
        tenantScope: 'org_alpha',
        actorPersona: 'dual_member',
        roleLabel: 'admin',
        endpoint: '/api/v1/exports',
        method: 'POST',
        edgeBindingKind: 'state_transition_binding',
      },
      {
        hopIndex: 2,
        hopReceiptId: 'hop-rcpt-2',
        capabilityId: 'cap:hop_2:signed_url',
        kind: 'signed_artifact_or_url',
        surface: 'async_job',
        serviceOrigin: 'https://worker.example.test',
        tenantScope: 'org_beta',
        actorPersona: 'dual_member',
        roleLabel: 'viewer',
        endpoint: '/api/v1/exports/status',
        method: 'GET',
        edgeBindingKind: 'async_pivot_binding',
      },
    ],
    nextTarget: {
      targetSurfaceKey: 'https://storage.example.test|storage|/files/archive',
      surface: 'storage',
      serviceOrigin: 'https://storage.example.test',
      endpoint: '/files/archive',
      method: 'GET',
      hypothesisClass: 'dual_tenant_abac',
      expectedBindingKind: 'value_binding',
      targetTenantScope: 'org_alpha',
      targetRoleLabel: 'owner',
      goalSummary: 'Use cap:hop_2:signed_url to verify cross-tenant object boundary.',
    },
    feasibilityProb: 0.78,
    terminalImpactWeight: 10,
    surfaceNovelty: 1.4,
    attemptsOnBranch: 1,
    consecutiveFailedAttempts: 0,
    createdWave: 1,
    lastUpdatedWave: 2,
  }
}

function sampleCodeSlice(): CodeDataflowSlice {
  return {
    route: 'GET /files/archive',
    mounts: ['/files'],
    methods: ['GET'],
    input: { params: ['bucket', 'key'] },
    auth: 'guarded',
    guards: ['requireSignedUrl'],
    root: 'services/storage/src/',
    hops: [
      { at: 'routes.ts:22', kind: 'route' },
      { at: 'handlers/archive.ts:44' },
      { at: 'lib/prefix-check.ts:19' },
      { at: 'lib/storage-read.ts:61' },
    ],
    sink: { at: 'lib/storage-read.ts:61', kind: 'file' },
  }
}

test('assignment-brief embeds frontier-scheduler hopCheckpoint cleanly within 2 KB checkpoint and 4 KB total budgets', () => {
  const built = buildHopCheckpointBrief(sampleFrontierBranch(), 8.4)
  const packet = buildAssignmentBriefPacket({
    missionKind: 'multihop_chain',
    origin: 'https://storage.example.test',
    routes: [{ method: 'GET', path: '/files/archive', params: ['key'], riskScore: 88 }],
    personas: [{ handle: 'dual_member', role: 'admin@org_alpha / viewer@org_beta' }],
    codeSlice: sampleCodeSlice(),
    codeExpansion: 'full',
    hopCheckpoint: built.brief,
    turnBudget: 24,
  })

  assert.ok(packet.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE, `brief ${packet.bytes} B exceeds 4 KB`)
  const parsed = JSON.parse(packet.text) as {
    mission: string
    hopCheckpoint?: RenderedHopCheckpoint
    code?: CodeDataflowSlice
  }
  assert.equal(parsed.mission, 'multihop_chain')
  assert.ok(parsed.hopCheckpoint, 'hopCheckpoint must be embedded in the brief')
  const cpBytes = Buffer.byteLength(JSON.stringify(parsed.hopCheckpoint), 'utf8')
  assert.ok(cpBytes <= ASSIGNMENT_BRIEF_HOP_CHECKPOINT_MAX_BYTES, `hopCheckpoint ${cpBytes} B exceeds 2 KB`)
  assert.equal(parsed.hopCheckpoint.schema, HOP_CHECKPOINT_SCHEMA_V1)
  assert.equal(parsed.hopCheckpoint.doNotRediscover, true)
  assert.equal(parsed.hopCheckpoint.depth, 2)
  assert.equal(parsed.hopCheckpoint.targetHop, 3)
  assert.deepEqual(parsed.hopCheckpoint.capabilityHandles, [
    'cap:hop_1:export_handle',
    'cap:hop_2:signed_url',
  ])
  assert.equal(parsed.hopCheckpoint.verifiedHops.length, 2)
  assert.equal(parsed.hopCheckpoint.nextGoal.endpoint, '/files/archive')
  assert.ok(parsed.hopCheckpoint.nextGoal.goal.includes('cap:hop_2:signed_url'))
  assert.ok(parsed.code, 'code slice coexists with hopCheckpoint inside 4 KB budget')
})

test('fitHopCheckpointForBrief and buildAssignmentBriefPacket strictly enforce <= 2 KB checkpoint and <= 4 KB brief under stress', () => {
  const oversizedCheckpoint: AssignmentBriefHopCheckpoint = {
    branchKey: `branch-stress-unicode-🔥-αβγ-${'x'.repeat(120)}`,
    depth: 6,
    targetHop: 6,
    mode: 'fuse',
    evi: 12.3456789,
    fuseWithBranchKey: `other-branch-${'y'.repeat(120)}`,
    verifiedHops: Array.from({ length: 8 }, (_, i) => ({
      hop: i + 1,
      receiptId: `hop-receipt-${i + 1}-${'r'.repeat(40)}`,
      capId: `cap:hop_${i + 1}:slot_${i + 1}`,
      kind: 'signed_artifact_or_url',
      surface: 'async_job',
      service: `https://service-${i + 1}.example.test`,
      tenant: `tenant_${i + 1}_long_scope_name`,
      actor: `actor_persona_${i + 1}`,
      role: 'member_with_long_role_label',
      at: `POST /api/v2/workflows/${i + 1}/execute/step`,
      binding: 'derived_crypto_binding',
    })),
    capabilityHandles: Array.from({ length: 12 }, (_, i) => `cap:hop_${i + 1}:derived_cap_${i + 1}`),
    prunedBranches: Array.from({ length: 8 }, (_, i) => ({
      surface: `https://edge-${i}.example.test|http|/api/v1/hardened-${i}`,
      hypothesis: `hardened_hypothesis_${i}_${'h'.repeat(40)}`,
      reason: 'invariant_enforced_hardened',
    })),
    nextGoal: {
      targetSurfaceKey: `https://terminal.example.test|http|/api/v2/settlements/finalize/${'z'.repeat(80)}`,
      surface: 'http',
      service: 'https://terminal.example.test',
      endpoint: `/api/v2/settlements/finalize/${'p'.repeat(120)}`,
      method: 'POST',
      hypothesisClass: 'economic_conservation',
      expectedBinding: 'state_transition_binding',
      targetTenant: 'org_target_long_scope_identifier',
      targetRole: 'finance_approver',
      goal: `Verify multi-hop terminal state conservation across 🔥 unicode boundaries ${'detail '.repeat(80)}`,
    },
    doNotRediscover: true,
  }

  const fitted = fitHopCheckpointForBrief(oversizedCheckpoint)
  assert.ok(fitted.bytes <= ASSIGNMENT_BRIEF_HOP_CHECKPOINT_MAX_BYTES, `fitted ${fitted.bytes} B exceeds 2048 B`)
  assert.equal(fitted.checkpoint.doNotRediscover, true)
  assert.equal(fitted.truncated, true)

  const tightFitted = fitHopCheckpointForBrief(oversizedCheckpoint, 512)
  assert.ok(tightFitted.bytes <= 512)
  assert.equal(tightFitted.checkpoint.doNotRediscover, true)

  // Full packet with massive routes, linkedRoutes, personas, codeSlice, and oversized checkpoint stays <= 4 KB.
  const fullPacket = buildAssignmentBriefPacket({
    missionKind: 'chain_step_2',
    origin: 'https://terminal.example.test',
    routes: Array.from({ length: 12 }, (_, i) => ({
      method: 'POST',
      path: `/api/v2/route-${i}/action`,
      params: ['id', 'amount', 'tenantId', 'nonce', 'signature'],
      riskScore: 90 - i,
    })),
    linkedRoutes: Array.from({ length: 8 }, (_, i) => ({
      method: 'GET',
      path: `/api/v2/linked-${i}/status`,
      params: ['jobId'],
    })),
    personas: Array.from({ length: 6 }, (_, i) => ({
      handle: `persona_${i}`,
      role: `role_${i}`,
      harvestedIds: [`obj-${i}-a`, `obj-${i}-b`, `obj-${i}-c`],
    })),
    codeSlice: sampleCodeSlice(),
    codeExpansion: 'full',
    hopCheckpoint: oversizedCheckpoint,
    proofObligation: {
      route: 'POST /api/v2/settlements/finalize',
      params: ['id', 'amount'],
      auth: 'guarded',
      sink: 'db_query@settlements.ts:112',
      chain: 'routes.ts:10 -> service.ts:44 -> settlements.ts:112',
      controlPersona: 'member_a',
      variantPersona: 'member_b',
      deliverable: 'Submit ctx.prove_composite DAG or record_coverage(proofGapReason="invariant_enforced_hardened").',
    },
  })

  assert.ok(fullPacket.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)
  const parsed = JSON.parse(fullPacket.text) as { hopCheckpoint?: RenderedHopCheckpoint }
  assert.ok(parsed.hopCheckpoint, 'hopCheckpoint survives inside 4 KB packet')
  assert.ok(
    measureAssignmentBriefBytes(JSON.stringify(parsed.hopCheckpoint)) <= ASSIGNMENT_BRIEF_HOP_CHECKPOINT_MAX_BYTES,
  )
  assert.equal(parsed.hopCheckpoint.doNotRediscover, true)

  // Even a caller-enforced compact cap (1536 B) succeeds with valid JSON <= 1536 B.
  const compactPacket = buildAssignmentBriefPacket(
    {
      missionKind: 'chain_step_2',
      origin: 'https://terminal.example.test',
      routes: [{ method: 'POST', path: '/api/v2/settlements/finalize' }],
      hopCheckpoint: oversizedCheckpoint,
    },
    ASSIGNMENT_BRIEF_MAX_BYTES,
  )
  assert.ok(compactPacket.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES)
  assert.doesNotThrow(() => JSON.parse(compactPacket.text))
})

test('hopCheckpoint scrubs all raw secret patterns while preserving valid opaque cap:... handles', () => {
  const syntheticJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsInJvbGUiOiJhZG1pbiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
  const syntheticApiKey = 'sk_live_99887766554433221100aabbccdd'
  const syntheticGhPat = 'ghp_1234567890abcdef1234567890abcdef1234'
  const syntheticOrKey = 'sk-or-v1-abcdef0123456789abcdef0123456789'
  const syntheticHexSecret = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
  const syntheticQuerySecret = 'supersecretqueryvalue987654'
  const syntheticSalt = 'rawsaltvalue778899'

  assert.equal(sanitizeCapabilityHandle('cap:hop_1:session_tok'), 'cap:hop_1:session_tok')
  assert.equal(sanitizeCapabilityHandle(syntheticJwt), '')
  assert.equal(sanitizeCapabilityHandle(syntheticApiKey), '')
  assert.equal(sanitizeCapabilityHandle(`Bearer ${syntheticApiKey}`), '')

  const leakyCheckpoint: AssignmentBriefHopCheckpoint = {
    branchKey: `branch-${syntheticApiKey}`,
    depth: 2,
    verifiedHops: [
      {
        hop: 1,
        receiptId: 'hop-1',
        capId: 'cap:hop_1:session_tok',
        surface: 'http',
        service: 'https://api.example.test',
        actor: 'member_a',
        at: `GET /api/signed?token=${syntheticQuerySecret}&sig=${syntheticHexSecret}`,
      },
      {
        hop: 2,
        receiptId: 'hop-2',
        // Accidentally passed raw JWT instead of opaque handle!
        capId: syntheticJwt,
        surface: 'webhook',
        service: 'https://worker.example.test',
        actor: 'member_a',
        at: `POST /hooks/${syntheticApiKey}?secret=${syntheticSalt}`,
      },
    ],
    capabilityHandles: [
      'cap:hop_1:session_tok',
      'cap:hop_2:signing_salt',
      syntheticJwt,
      syntheticApiKey,
      syntheticGhPat,
      `Bearer ${syntheticOrKey}`,
      syntheticHexSecret,
    ],
    prunedBranches: [
      {
        surface: `https://api.example.test|http|/admin?token=${syntheticQuerySecret}`,
        hypothesis: `signing_salt=${syntheticSalt}`,
        reason: 'invariant_enforced_hardened',
      },
    ],
    nextGoal: {
      surface: 'http',
      service: 'https://api.example.test',
      endpoint: `/api/v1/export/download?token=${syntheticQuerySecret}&api_key=${syntheticApiKey}`,
      method: 'GET',
      goal: `Use cap:hop_2:signing_salt (never ${syntheticJwt} or Bearer ${syntheticOrKey} or ${syntheticGhPat} or signing_salt=${syntheticSalt} or ${syntheticHexSecret})`,
    },
    doNotRediscover: true,
  }

  const packet = buildAssignmentBriefPacket({
    missionKind: 'multihop_chain',
    origin: 'https://api.example.test',
    routes: [{ method: 'GET', path: '/api/v1/export/download' }],
    hopCheckpoint: leakyCheckpoint,
  })

  // ZERO raw secrets may survive anywhere in the rendered brief.
  for (const forbidden of [
    syntheticJwt,
    syntheticApiKey,
    syntheticGhPat,
    syntheticOrKey,
    syntheticHexSecret,
    syntheticQuerySecret,
    syntheticSalt,
  ]) {
    assert.equal(
      packet.text.includes(forbidden),
      false,
      `Raw secret leaked into rendered AssignmentBrief: ${forbidden.slice(0, 12)}...`,
    )
  }

  // Valid opaque handles survive intact.
  const parsed = JSON.parse(packet.text) as { hopCheckpoint: RenderedHopCheckpoint }
  assert.deepEqual(parsed.hopCheckpoint.capabilityHandles, [
    'cap:hop_1:session_tok',
    'cap:hop_2:signing_salt',
  ])
  assert.equal(parsed.hopCheckpoint.verifiedHops[0]?.capId, 'cap:hop_1:session_tok')
  assert.equal(parsed.hopCheckpoint.verifiedHops[1]?.capId, 'cap:redacted:hop_2')
  assert.equal(parsed.hopCheckpoint.nextGoal.endpoint, '/api/v1/export/download')
  assert.ok(parsed.hopCheckpoint.nextGoal.goal.includes('cap:hop_2:signing_salt'))
  assert.equal(parsed.hopCheckpoint.doNotRediscover, true)
})
