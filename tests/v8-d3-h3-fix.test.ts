/**
 * Regression suite for Queue #22 blockers (Blocker 1: partial-hop decoy FP closure;
 * Blocker 2: H2->H3+ crypto & async SDK helper discoverability).
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
  buildAssignmentBriefPacket,
  type AssignmentBriefMultiHopContract,
} from '../src/server/assignment-brief.ts'
import {
  signHostRecord,
  verifyCompositeReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import {
  MULTIHOP_CHAINS_SKILL,
  clearSkillsCache,
  selectPreInjectionSkills,
} from '../src/server/skills.ts'
import {
  evaluateCrossSurfacePivot,
  evaluateDualTenantAbac,
  evaluateParserCacheDifferential,
  isJobOrHandleStub,
  type HostSignedRecord,
} from '../src/server/v8-oracle-families.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const SIGNING_KEY = 'unit-test-d3-h3-fix-signing-key-0123456789'

function makeSignedEntry(
  exchangeId: string,
  overrides: {
    arm: 'control' | 'probe'
    method: string
    pathAndQuery: string
    status: number
    timestampMs: number
    actorPersona?: string | null
    actorTenant?: string | null
    emittedCapabilities?: string[]
    consumedCapabilities?: string[]
    json?: unknown
    body?: string
    evidenceRole?: string
  },
): HostTranscriptEntry {
  const actor = overrides.actorPersona !== undefined ? overrides.actorPersona : 'dual_attacker'
  const tenant = overrides.actorTenant !== undefined ? overrides.actorTenant : 'org_attacker'
  const entry: HostTranscriptEntry = {
    exchangeId,
    timestampMs: overrides.timestampMs,
    actorPersona: actor,
    actorRoleLabel: actor ? `member (${tenant ?? 'org_attacker'})` : null,
    cleanSession: true,
    ...(overrides.emittedCapabilities ? { emittedCapabilities: overrides.emittedCapabilities } : {}),
    ...(overrides.consumedCapabilities ? { consumedCapabilities: overrides.consumedCapabilities } : {}),
    ...(overrides.evidenceRole ? { evidenceRole: overrides.evidenceRole } : {}),
    step: {
      id: exchangeId,
      arm: overrides.arm,
      method: overrides.method,
      route: overrides.pathAndQuery.split('?')[0]!,
      pathAndQuery: overrides.pathAndQuery,
      status: overrides.status,
      actor: { handle: actor, role: actor ? 'member' : null, tenant, auth: actor ? 'bearer' : 'unknown', sameSite: null },
      ...(overrides.json !== undefined ? { json: overrides.json } : {}),
      ...(overrides.body !== undefined ? { body: overrides.body } : {}),
    },
  }
  return { ...entry, hostSignature: signHostRecord(entry, SIGNING_KEY) }
}

function mkOracleRec(id: string, ts: number, status: number, extra: Partial<HostSignedRecord> = {}): HostSignedRecord {
  return { id, hostSignature: 'sig-1234567890abcdef', timestampMs: ts, status, ...extra }
}

// ============================================================================
// 1. Recursive isJobOrHandleStub catches nested export/URL/cache stubs
// ============================================================================

test('isJobOrHandleStub rejects nested export/signedUrl/cache/own-tenant stubs and accepts real foreign data', () => {
  const nestedExportStub = { data: { export: { id: 'exp-77', signedUrl: 'https://cdn.example.test/org_attacker/exp-77.csv', status: 'ready' } } }
  const wrappedJobStub = { ok: true, export: { id: 'exp-88', url: '/api/exports/exp-88/download', status: 'queued', tenantPrefix: 'org_attacker/' } }
  const deepArtifactStub = { job: { id: 'j-9', state: 'completed', artifact: { presignedUrl: 'https://storage.example.test/j-9', objectKey: 'org_attacker/j-9.csv', expiresIn: 300 } } }
  const cacheAckStub = { status: 'ok', cache: { hit: true, key: 'perm:u1', ttl: 60 }, permissions: ['exports:create'] }
  const tokenExportStub = { jobId: 'exp-99', status: 'queued', tenantId: 'org_attacker', downloadUrl: '/api/exports/exp-99/download', exportToken: 'tok_exp_99' }

  assert.equal(isJobOrHandleStub(nestedExportStub, undefined, 200, 'GET'), true)
  assert.equal(isJobOrHandleStub(wrappedJobStub, undefined, 202, 'POST'), true)
  assert.equal(isJobOrHandleStub(deepArtifactStub, undefined, 200, 'GET'), true)
  assert.equal(isJobOrHandleStub(cacheAckStub, undefined, 200, 'GET'), true)
  assert.equal(isJobOrHandleStub(tokenExportStub, undefined, 202, 'POST'), true)
  assert.equal(isJobOrHandleStub(undefined, 'https://storage.example.test/org_attacker/exp-1.csv?sig=abc', 200, 'GET'), true)
  assert.equal(isJobOrHandleStub(undefined, JSON.stringify(nestedExportStub), 200, 'GET'), true)

  // Genuine foreign-tenant records and mutation readbacks MUST NOT be misclassified as stubs.
  assert.equal(isJobOrHandleStub({ data: { tenantId: 'org_victim', records: [{ id: 'inv-1', amountCents: 42000 }] } }, undefined, 200, 'GET'), false)
  assert.equal(isJobOrHandleStub({ tenantId: 'org_victim', records: [{ id: 'r1', ownerEmail: 'finance@victim.test' }] }, undefined, 200, 'GET'), false)
  assert.equal(isJobOrHandleStub({ id: 'po-1', status: 'approved', amount: 5000 }, undefined, 200, 'GET'), false)
  assert.equal(isJobOrHandleStub({ role: 'owner' }, undefined, 200, 'GET'), false)
})

// ============================================================================
// 2. Nested export stub REJECTED across ALL oracle paths & generic classes
// ============================================================================

test('nested { data: { export: { id, signedUrl, status } } } stub is REJECTED across ALL oracle paths including cross_surface_pivot, dual_tenant_abac, parser_cache_differential, and generic classes', () => {
  const cap = 'cap:hop_1:cache_prime_tok'
  const nestedStub = { data: { export: { id: 'exp-decoy-1', signedUrl: 'https://cdn.example.test/org_attacker/exp-decoy-1.csv', status: 'ready', tenantId: 'org_attacker' } } }
  const transcript: HostSignedTranscript = {
    entries: [
      makeSignedEntry('ex-ctrl-export', { arm: 'control', method: 'POST', pathAndQuery: '/api/exports', status: 403, timestampMs: 900 }),
      makeSignedEntry('ex-prime', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/me/permissions', status: 200, timestampMs: 1000,
        emittedCapabilities: [cap],
        json: { status: 'ok', tenantId: 'org_attacker', cache: { hit: true, ttl: 60 }, permissions: ['exports:create'] },
      }),
      makeSignedEntry('ex-export-stub', {
        arm: 'probe', method: 'POST', pathAndQuery: '/api/exports', status: 201, timestampMs: 1100,
        consumedCapabilities: [cap],
        json: nestedStub,
      }),
      makeSignedEntry('ex-status-poll-stub', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/exports/exp-decoy-1', status: 200, timestampMs: 1200,
        json: { data: { export: { id: 'exp-decoy-1', signedUrl: 'https://cdn.example.test/org_attacker/exp-decoy-1.csv', status: 'completed', tenantId: 'org_attacker' } } },
      }),
    ],
  }

  const allClasses = [
    'cross_surface_pivot',
    'dual_tenant_abac',
    'parser_cache_differential',
    'broken_access_control',
    'cross_tenant_export',
    'CWE-200',
    'CWE-284',
    'CWE-639',
    'CWE-863',
    'custom_generic_export_bypass',
  ]

  for (const vulnClass of allClasses) {
    const receipt = {
      chainId: `chain-nested-stub-${vulnClass}`,
      terminalVulnClass: vulnClass,
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/me/permissions' }, exchangeIds: ['ex-prime'], producedCapabilities: [cap], claimedDelta: 'Primed permission cache on own tenant.' },
        { hopId: 'hop_2', surface: 'async_job', target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/api/exports' }, exchangeIds: ['ex-export-stub'], consumedCapabilities: [cap], claimedDelta: 'Created export job returning nested signedUrl stub.' },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
      terminalImpact: {
        terminalHopId: 'hop_2',
        summary: 'Cache prime allowed export creation returning nested signed URL stub.',
        terminalExchangeId: 'ex-export-stub',
        preChainControlExchangeIds: ['ex-ctrl-export'],
        postChainReadbackExchangeIds: ['ex-status-poll-stub'],
      },
      replayMode: 'fresh_clean_replay',
    }
    const res = verifyCompositeReceipt(receipt, transcript, { attackerPersonas: ['dual_attacker'], signingKey: SIGNING_KEY })
    assert.equal(res.confirmed, false, `Nested export stub MUST be rejected for ${vulnClass}`)
    assert.equal(res.failedStage, 'terminal_impact')
    assert.equal(res.rejectedBy, 'terminal_impact_unproven', `Expected terminal_impact_unproven for ${vulnClass}, got ${res.rejectedBy}: ${res.reason}`)
    const hintText = res.missingEvidence?.join(' ') ?? ''
    assert.match(hintText, /ctx\.seal_capability/, `Hint for ${vulnClass} must mention ctx.seal_capability`)
    assert.match(hintText, /invariant_enforced_hardened/, `Hint for ${vulnClass} must mention invariant_enforced_hardened`)
  }

  // Direct v8-oracle-families checks with nested stub across cross_surface_pivot, dual_tenant_abac, and parser_cache_differential
  const directPivot = evaluateCrossSurfacePivot({
    attackerOriginPersona: { actorId: 'dual_attacker', role: 'member', tenantId: 'org_attacker' },
    preChainControlDenied: mkOracleRec('c1', 900, 403, { route: '/api/exports' }),
    hops: [
      { surface: 'http', role: 'trigger_write', emittedArtifactDigest: cap, record: mkOracleRec('h1', 1000, 200, { actorId: 'dual_attacker', capabilityHandle: cap }) },
      { surface: 'async_job', role: 'terminal_impact', bindingKind: 'value_binding', consumedArtifactDigest: cap, record: mkOracleRec('h2', 1100, 201, { method: 'POST', json: nestedStub }) },
    ],
    terminalImpact: { kind: 'privileged_read', verified: true, impactDigest: 'sha256:stub' },
  })
  assert.equal(directPivot.satisfied, false)
  assert.equal(directPivot.reason, 'terminal_impact_unproven_intermediate_stub')

  const directDual = evaluateDualTenantAbac({
    mode: 'dual_org_cache_bleed',
    actor: { actorId: 'dual_attacker', rolesByTenant: { org_attacker: 'admin', org_victim: 'viewer' } },
    primeTenantId: 'org_attacker',
    targetTenantId: 'org_victim',
    baselineDeniedControl: mkOracleRec('c1', 900, 403),
    primeAction: mkOracleRec('p1', 1000, 200),
    bledAccess: mkOracleRec('b1', 1100, 200, { method: 'GET', json: nestedStub }),
    targetRecordId: 'exp-decoy-1',
  })
  assert.equal(directDual.satisfied, false)
  assert.equal(directDual.reason, 'terminal_impact_unproven_intermediate_stub')

  const directOwnTenantDual = evaluateDualTenantAbac({
    mode: 'dual_org_cache_bleed',
    actor: { actorId: 'dual_attacker', rolesByTenant: { org_attacker: 'admin', org_victim: 'viewer' } },
    primeTenantId: 'org_attacker',
    targetTenantId: 'org_victim',
    baselineDeniedControl: mkOracleRec('c1', 900, 403),
    primeAction: mkOracleRec('p1', 1000, 200),
    bledAccess: mkOracleRec('b1', 1100, 200, { method: 'GET', json: { tenantId: 'org_attacker', records: [{ id: 'own-1' }] } }),
  })
  assert.equal(directOwnTenantDual.satisfied, false)
  assert.equal(directOwnTenantDual.reason, 'bled_access_own_tenant_only')

  const directCache = evaluateParserCacheDifferential({
    mode: 'cache_primed',
    cacheKey: 'export:1',
    victimArtifactDigest: 'sha256:stub',
    cleanControl: mkOracleRec('cc1', 900, 403),
    victimOrPrimeRequest: mkOracleRec('vp1', 1000, 200, { actorId: 'victim', tenantId: 'org_victim' }),
    attackerProbe: mkOracleRec('ap1', 1100, 200, { actorId: 'dual_attacker', tenantId: 'org_attacker', artifactDigest: 'sha256:stub', json: nestedStub }),
    cacheHitObserved: true,
  })
  assert.equal(directCache.satisfied, false)
  assert.equal(directCache.reason, 'terminal_impact_unproven_intermediate_stub')
})

// ============================================================================
// 3. Exact terminal denied-control, anti-spoofing, forged oracleInput, and true-positive PASS
// ============================================================================

test('composite.verify enforces exact terminal denied control, blocks unauth 401 / forged oracleInput / own-tenant-only, and confirms genuine foreign-tenant data download', () => {
  const cap1 = 'cap:hop_1:cache_tok'
  const cap2 = 'cap:hop_2:signed_export_url'
  const transcript: HostSignedTranscript = {
    entries: [
      makeSignedEntry('ex-ctrl-terminal-403', { arm: 'control', method: 'GET', pathAndQuery: '/api/exports/exp-99/download', status: 403, timestampMs: 800 }),
      makeSignedEntry('ex-ctrl-other-route-403', { arm: 'control', method: 'GET', pathAndQuery: '/api/other-endpoint', status: 403, timestampMs: 810 }),
      makeSignedEntry('ex-ctrl-anon-401', { arm: 'control', method: 'GET', pathAndQuery: '/api/exports/exp-99/download', status: 401, timestampMs: 820, actorPersona: null, actorTenant: null }),
      makeSignedEntry('ex-hop1', { arm: 'probe', method: 'GET', pathAndQuery: '/api/me/permissions', status: 200, timestampMs: 1000, emittedCapabilities: [cap1], json: { cached: true, permissions: ['exports:create'] } }),
      makeSignedEntry('ex-hop2', { arm: 'probe', method: 'POST', pathAndQuery: '/api/exports', status: 202, timestampMs: 1100, consumedCapabilities: [cap1], emittedCapabilities: [cap2], json: { data: { export: { id: 'exp-99', signedUrl: '/api/exports/exp-99/download', status: 'queued' } } } }),
      makeSignedEntry('ex-hop3-victim-data', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/exports/exp-99/download', status: 200, timestampMs: 1200, consumedCapabilities: [cap2],
        json: { data: { tenantId: 'org_victim', records: [{ id: 'inv-9001', ownerEmail: 'cfo@victim.test', amountCents: 995000 }] } },
      }),
      makeSignedEntry('ex-hop3-own-tenant', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/exports/exp-99/download', status: 200, timestampMs: 1210, consumedCapabilities: [cap2],
        json: { data: { tenantId: 'org_attacker', records: [{ id: 'inv-own-1', ownerEmail: 'me@attacker.test', amountCents: 100 }] } },
      }),
      makeSignedEntry('ex-cap-op', {
        arm: 'probe', method: 'POST', pathAndQuery: '/capability/seal', status: 200, timestampMs: 1220, consumedCapabilities: [cap2], evidenceRole: 'host_capability_op',
      }),
    ],
  }

  const buildChain = (opts: { vulnClass?: string; termExId?: string; ctrlIds?: string[]; termSurface?: string; oracleInput?: Record<string, unknown> }) => ({
    chainId: `chain-strict-${opts.vulnClass ?? 'dual'}`,
    terminalVulnClass: opts.vulnClass ?? 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/me/permissions' }, exchangeIds: ['ex-hop1'], producedCapabilities: [cap1], claimedDelta: 'Primed own permission cache.' },
      { hopId: 'hop_2', surface: 'async_job', target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/api/exports' }, exchangeIds: ['ex-hop2'], consumedCapabilities: [cap1], producedCapabilities: [cap2], claimedDelta: 'Created export handle.' },
      { hopId: 'hop_3', surface: opts.termSurface ?? 'storage', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/exports/exp-99/download' }, exchangeIds: [opts.termExId ?? 'ex-hop3-victim-data'], consumedCapabilities: [cap2], claimedDelta: 'Downloaded foreign victim tenant export data.' },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap1 },
      { kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_3', capabilityHandle: cap2 },
    ],
    terminalImpact: {
      terminalHopId: 'hop_3',
      summary: 'Cross-tenant download exposed confidential org_victim invoice records via derived signed URL.',
      terminalExchangeId: opts.termExId ?? 'ex-hop3-victim-data',
      preChainControlExchangeIds: opts.ctrlIds ?? ['ex-ctrl-terminal-403'],
      ...(opts.oracleInput ? { oracleInput: opts.oracleInput } : {}),
    },
    replayMode: 'fresh_clean_replay',
  })

  // (a) Mismatched-route 403 control MUST fail closed!
  const wrongRouteCtrl = verifyCompositeReceipt(buildChain({ ctrlIds: ['ex-ctrl-other-route-403'] }), transcript, { attackerPersonas: ['dual_attacker'], signingKey: SIGNING_KEY })
  assert.equal(wrongRouteCtrl.confirmed, false)
  assert.equal(wrongRouteCtrl.rejectedBy, 'terminal_impact_unproven')

  // (b) Unauthenticated 401 control for authenticated attacker probe MUST fail closed!
  const anonCtrl = verifyCompositeReceipt(buildChain({ ctrlIds: ['ex-ctrl-anon-401'] }), transcript, { attackerPersonas: ['dual_attacker'], signingKey: SIGNING_KEY })
  assert.equal(anonCtrl.confirmed, false)
  assert.equal(anonCtrl.rejectedBy, 'terminal_impact_unproven')

  // (c) Own-tenant-only download MUST fail closed even with valid 403 control!
  const ownTenant = verifyCompositeReceipt(buildChain({ termExId: 'ex-hop3-own-tenant' }), transcript, { attackerPersonas: ['dual_attacker'], signingKey: SIGNING_KEY })
  assert.equal(ownTenant.confirmed, false)
  assert.equal(ownTenant.rejectedBy, 'terminal_impact_unproven')

  // (d) Synthetic host_capability_op exchange as terminalExchangeId MUST fail closed!
  const capOpTerm = verifyCompositeReceipt(buildChain({ termExId: 'ex-cap-op' }), transcript, { attackerPersonas: ['dual_attacker'], signingKey: SIGNING_KEY })
  assert.equal(capOpTerm.confirmed, false)
  assert.equal(capOpTerm.rejectedBy, 'terminal_impact_unproven')

  // (e) Forged oracleInput referencing records absent from host-signed transcript MUST fail closed!
  const forgedOracle = verifyCompositeReceipt(buildChain({
    vulnClass: 'dual_tenant_abac',
    oracleInput: {
      mode: 'dual_org_cache_bleed',
      actor: { actorId: 'dual_attacker', rolesByTenant: { org_attacker: 'admin', org_victim: 'viewer' } },
      primeTenantId: 'org_attacker',
      targetTenantId: 'org_victim',
      baselineDeniedControl: mkOracleRec('forged-ctrl', 800, 403),
      primeAction: mkOracleRec('forged-prime', 1000, 200),
      bledAccess: mkOracleRec('forged-bled', 1200, 200, { artifactDigest: 'sha256:victim' }),
      observedTenantId: 'org_victim',
    },
  }), transcript, { attackerPersonas: ['dual_attacker'], signingKey: SIGNING_KEY })
  assert.equal(forgedOracle.confirmed, false)
  assert.match(forgedOracle.reason, /invalid_.*_signature/)

  // (f) True positive: genuine victim-tenant data download + exact terminal 403 control PASSES across all families!
  for (const vulnClass of ['dual_tenant_abac', 'parser_cache_differential', 'cross_surface_pivot', 'cross_tenant_export']) {
    const pass = verifyCompositeReceipt(buildChain({ vulnClass }), transcript, { attackerPersonas: ['dual_attacker'], signingKey: SIGNING_KEY })
    assert.equal(pass.confirmed, true, `True victim data download must pass for ${vulnClass}: ${pass.reason}`)
  }
})

// ============================================================================
// 4. Blocker 2: H2->H3+ crypto & async SDK helper discoverability & caps
// ============================================================================

test('assignment-brief surfaces exact 1-line ctx.hmac_sign/ctx.jwt_sign/ctx.await_async patterns and continueChainRule within 4 KB cap', () => {
  // Webhook + HMAC + JWT chain brief
  const cryptoPacket = buildAssignmentBriefPacket({
    missionKind: 'multihop_chain',
    origin: 'https://api.example.test',
    routes: [
      { method: 'GET', path: '/api/runtime/signing-config', riskScore: 85 },
      { method: 'POST', path: '/api/webhooks/settlement', params: ['signature', 'payload'], riskScore: 95 },
    ],
    personas: [{ handle: 'member_b', role: 'member (org_b)' }],
    hopCheckpoint: {
      branchKey: 'branch-webhook-hmac',
      depth: 1,
      verifiedHops: [{ hop: 1, receiptId: 'h1', capId: 'cap:hop_1:signing_key', surface: 'http', actor: 'member_b' }],
      capabilityHandles: ['cap:hop_1:signing_key'],
      nextGoal: { endpoint: 'POST /api/webhooks/settlement', surface: 'webhook', goal: 'Sign settlement webhook payload with HMAC and forge scoped JWT.' },
      doNotRediscover: true,
    },
  })
  assert.ok(cryptoPacket.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)
  const cryptoParsed = JSON.parse(cryptoPacket.text) as { multiHopProofContract?: AssignmentBriefMultiHopContract }
  assert.ok(cryptoParsed.multiHopProofContract)
  assert.match(cryptoParsed.multiHopProofContract.continueChainRule, /ctx\.seal_capability.*terminalHopId/i)
  assert.equal(cryptoPacket.text.includes('fast_lab'), false, 'brief must not hardcode profile: "fast_lab"')

  // Async export / PDF worker chain brief (uncompacted full contract includes optionalHelpers without fast_lab)
  const asyncPacket = buildAssignmentBriefPacket({
    missionKind: 'chain_step_2',
    origin: 'https://api.example.test',
    routes: [
      { method: 'POST', path: '/api/exports/pdf', params: ['templateUrl'], riskScore: 90 },
      { method: 'GET', path: '/api/jobs/:id', riskScore: 80 },
    ],
    personas: [{ handle: 'member_b', role: 'member (org_b)' }],
  })
  assert.ok(asyncPacket.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)
  const asyncParsed = JSON.parse(asyncPacket.text) as { multiHopProofContract?: AssignmentBriefMultiHopContract }
  const asyncHelpers = asyncParsed.multiHopProofContract?.optionalHelpers ?? ''
  assert.ok(asyncHelpers.includes('ctx.hmac_sign({ secretHandle'), `missing hmac_sign helper note: ${asyncHelpers}`)
  assert.ok(asyncHelpers.includes('ctx.jwt_sign({ secretHandle'), `missing jwt_sign helper note: ${asyncHelpers}`)
  assert.ok(asyncHelpers.includes('ctx.await_async({ pollRequest'), `missing await_async helper note: ${asyncHelpers}`)
  assert.ok(asyncHelpers.includes('triggerExchangeId'), `missing triggerExchangeId in await_async note: ${asyncHelpers}`)
  assert.ok(asyncHelpers.includes('correlationId'), `missing correlationId in await_async note: ${asyncHelpers}`)
  assert.equal(asyncHelpers.includes('fast_lab'), false, 'optionalHelpers must not hardcode profile: "fast_lab"')

  // Pre-injected 1200-char multihop-chains excerpt includes ALL 5 helpers + hardened-twin rule + Hop-2 warning
  clearSkillsCache()
  const injected = selectPreInjectionSkills({ lane: 'chain', limit: 2 })
  const mh = injected.find(s => s.name === MULTIHOP_CHAINS_SKILL)
  assert.ok(mh, 'multihop-chains must be pre-injected')
  assert.ok(mh.excerpt.length <= 1200)
  for (const tok of ['ctx.seal_capability', 'ctx.hmac_sign', 'ctx.jwt_sign', 'ctx.await_async', 'ctx.prove_composite', 'invariant_enforced_hardened', 'link/token stubs']) {
    assert.ok(mh.excerpt.includes(tok), `1200-char multihop-chains excerpt missing "${tok}"`)
  }
})

// ============================================================================
// 5. LOC & Anti-Contamination Budgets
// ============================================================================

test('composite-receipt.ts and v8-oracle-families.ts stay <= 750 LOC with zero v8 contamination', () => {
  for (const rel of ['src/server/composite-receipt.ts', 'src/server/v8-oracle-families.ts']) {
    const loc = readFileSync(join(REPO_ROOT, rel), 'utf8').trimEnd().split('\n').length
    assert.ok(loc <= 750, `${rel} is ${loc} LOC (must be <= 750)`)
  }
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `v8 contamination hits: ${JSON.stringify(scan.hits)}`)
})
