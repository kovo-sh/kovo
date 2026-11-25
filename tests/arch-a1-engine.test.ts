/**
 * Architecture Proposal A1 (Core Engine Quick Wins & v8 Bugfixes) regression suite.
 *
 * Verifies all 3 deliverables (Docker-free):
 *  1. Silent HopCheckpointBrief drop fixed + unified `v8.hop_checkpoint.v1` schema backed by
 *     SQLite CapabilityLedger (restart-safe, full <= 2 KB budget, no 480 B cap, no 'artifact' skip)
 *     + dead `Execution.evaluateFrontierProgressForRound` removed (`execution.ts < 6,000 LOC`).
 *  2. ESM circular `createRequire` / `loadCompositeModule` / `verifyReceiptUnified` removed from
 *     `proof-receipt.ts`, and `verifyCompositeReceipt()` dispatches `evaluateV8OracleFamily()` by
 *     default for v8 oracle families (`composite-receipt.ts <= 750 LOC`).
 *  3. Copy-pasted `runV8AgentScriptProof` fork collapsed into unified `runAgentScriptProof()`
 *     (zero monkey-patching) and `retestPersistedAgentScript()` reproduces & detects fixes on
 *     multi-hop v8 `CompositeProofReceipt` proof scripts.
 */
import assert from 'node:assert/strict'
import { createHash, createHmac } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { runAgentScriptProof, retestPersistedAgentScript } from '../src/server/agent-script-proof.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import {
  DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES,
  formatDerivedCapabilityHandle,
} from '../src/server/capability-ledger.ts'
import {
  signHostRecord,
  verifyCompositeReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import {
  CHECKPOINT_CAP_SKILL_PREFIX,
  extractCheckpointCapIdFromStep,
} from '../src/server/exec-recon-planner.ts'
import { Execution, runV8AgentScriptProof } from '../src/server/execution.ts'
import { buildHopCheckpointBrief, type FrontierBranch } from '../src/server/frontier-scheduler.ts'
import { dispatchInvestigations } from '../src/server/graph-coordinator.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { Store } from '../src/server/store.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_NAME,
} from '../src/server/verify-rpc.ts'
import type {
  VerifyScriptRequest,
  VerifyScriptResult,
  WorkerBackend,
  WorkerSession,
  WorkerSessionOptions,
} from '../src/server/worker-backend.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const SIGNING_KEY = 'a1-engine-test-hmac-key-0123456789abcdef'

function makeStore(t: { after: (fn: () => void) => void }): { storage: Store; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-arch-a1-'))
  const storage = new Store(dir)
  t.after(() => {
    try { storage.close() } catch { /* already closed in restart test */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return { storage, dir }
}

function makeSignedEntry(
  exchangeId: string,
  overrides: {
    arm?: 'control' | 'probe'
    method?: string
    pathAndQuery?: string
    status?: number
    timestampMs?: number
    actorPersona?: string
    tenant?: string
    emittedCapabilities?: string[]
    consumedCapabilities?: string[]
    json?: unknown
    body?: string
  } = {},
): HostTranscriptEntry {
  const entry: HostTranscriptEntry = {
    exchangeId,
    timestampMs: overrides.timestampMs ?? 1000,
    actorPersona: overrides.actorPersona ?? 'member_a',
    ...(overrides.emittedCapabilities ? { emittedCapabilities: overrides.emittedCapabilities } : {}),
    ...(overrides.consumedCapabilities ? { consumedCapabilities: overrides.consumedCapabilities } : {}),
    cleanSession: true,
    step: {
      id: exchangeId,
      arm: overrides.arm ?? 'probe',
      method: overrides.method ?? 'GET',
      route: (overrides.pathAndQuery ?? '/api/items').split('?')[0]!,
      pathAndQuery: overrides.pathAndQuery ?? '/api/items',
      status: overrides.status ?? 200,
      actor: {
        handle: overrides.actorPersona ?? 'member_a',
        role: 'member',
        tenant: overrides.tenant ?? 'org_a',
        auth: 'bearer',
        sameSite: null,
      },
      ...(overrides.json !== undefined ? { json: overrides.json } : {}),
      body: overrides.body ?? (overrides.json !== undefined ? JSON.stringify(overrides.json) : '{}'),
    },
  }
  return { ...entry, hostSignature: signHostRecord(entry, SIGNING_KEY) }
}

function rpcCall(
  socketPath: string,
  token: string,
  nonce: string,
  op: string,
  args: Record<string, unknown>,
): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  const payload = JSON.stringify({ op, args })
  return new Promise((resolvePromise, rejectPromise) => {
    const req = httpRequest({
      socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        [VERIFY_RPC_HEADER]: token,
        [VERIFY_NONCE_HEADER]: nonce,
      },
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', (c: Buffer) => chunks.push(c))
      res.on('end', () => {
        try {
          resolvePromise(JSON.parse(Buffer.concat(chunks).toString('utf8')) as { ok: boolean; result?: unknown; error?: string })
        } catch (err) {
          rejectPromise(err)
        }
      })
    })
    req.on('error', rejectPromise)
    req.end(payload)
  })
}

// ============================================================================
// 1. Deliverable 1: HopCheckpointBrief Persistence, Unified Schema & Dead Code
// ============================================================================

test('A1.1: persistDispatchPlan persists checkpointCapId/checkpointJson and assignmentBriefForStep hydrates full <= 2 KB SQLite ledger brief across restarts (no 480 B cap or artifact skip)', async (t) => {
  const { storage, dir } = makeStore(t)
  const origin = 'http://127.0.0.1:4101'
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab' })
  const run = storage.run(runId)

  // Seed a 3-hop causal chain in SQLite CapabilityLedger containing the word "artifact"
  // and rich lineage > 550 B to prove neither the 480 B truncation nor the 'artifact' skip occurs.
  const ledger = storage.capabilityLedger(runId)
  const cap1 = formatDerivedCapabilityHandle('a1_1', 'seed_artifact')
  const cap2 = formatDerivedCapabilityHandle('a1_2', 'signed_artifact')
  const cap3 = formatDerivedCapabilityHandle('a1_3', 'pivot_artifact')
  ledger.addCapability({
    capId: cap1,
    kind: 'identity_session',
    provenance: 'attacker_seed',
    tenantScope: 'org_alpha',
    actorPersona: 'member_alpha',
    serviceOrigin: origin,
    surface: 'http',
    artifactDigest: '1'.repeat(64),
    artifactSummary: 'Hop 1 attacker seed session with signed artifact metadata',
    createdAtMs: 1000,
  })
  ledger.addCapability({
    capId: cap2,
    kind: 'signed_artifact_or_url',
    provenance: 'derived_hop',
    tenantScope: 'org_alpha',
    actorPersona: 'member_alpha',
    serviceOrigin: origin,
    surface: 'async_job',
    artifactDigest: '2'.repeat(64),
    artifactSummary: 'Hop 2 derived signed artifact handle issued by export service',
    createdAtMs: 1100,
  })
  ledger.addCapability({
    capId: cap3,
    kind: 'scoped_token',
    provenance: 'derived_hop',
    tenantScope: 'org_beta',
    actorPersona: 'member_alpha',
    serviceOrigin: origin,
    surface: 'webhook',
    artifactDigest: '3'.repeat(64),
    artifactSummary: 'Hop 3 cross-tenant webhook artifact handle ready for terminal pivot',
    createdAtMs: 1200,
  })
  ledger.addCausalEdge({
    preconditionCapIds: [cap1],
    actorContext: { persona: 'member_alpha', tenantScope: 'org_alpha', serviceOrigin: origin },
    hopReceiptId: 'rcpt-hop-1-2',
    edgeBindingKind: 'value_binding',
    postconditionCapId: cap2,
    sourceTimestampMs: 1000,
    targetTimestampMs: 1100,
  })
  ledger.addCausalEdge({
    preconditionCapIds: [cap2],
    actorContext: { persona: 'member_alpha', tenantScope: 'org_beta', serviceOrigin: origin },
    hopReceiptId: 'rcpt-hop-2-3',
    edgeBindingKind: 'async_pivot_binding',
    postconditionCapId: cap3,
    sourceTimestampMs: 1100,
    targetTimestampMs: 1200,
  })

  // Verify ONE unified HopCheckpointBrief schema between CapabilityLedger and FrontierScheduler.
  const ledgerBrief = ledger.buildHopCheckpointBrief(cap3, DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES, {
    branchKey: 'branch-a1-artifact-pivot',
    evi: 6.75,
    nextGoal: {
      surface: 'http',
      service: origin,
      endpoint: '/api/v1/org-beta/exports/download',
      method: 'GET',
      hypothesisClass: 'dual_tenant_abac',
      goal: 'Follow derived webhook artifact handle to read foreign org_beta records without rediscovering Hop 1-2.',
    },
  })
  assert.equal(ledgerBrief.schema, 'v8.hop_checkpoint.v1')
  assert.equal(ledgerBrief.doNotRediscover, true)
  assert.equal(ledgerBrief.depth, 2)
  assert.ok(ledgerBrief.capabilityHandles.includes(cap3))

  const sampleBranch: FrontierBranch = {
    branchKey: 'branch-a1-artifact-pivot',
    depth: 2,
    verifiedHops: [
      { hopIndex: 1, hopReceiptId: 'rcpt-hop-1-2', capabilityId: cap2, kind: 'signed_artifact_or_url', surface: 'async_job', serviceOrigin: origin, tenantScope: 'org_alpha', actorPersona: 'member_alpha' },
      { hopIndex: 2, hopReceiptId: 'rcpt-hop-2-3', capabilityId: cap3, kind: 'scoped_token', surface: 'webhook', serviceOrigin: origin, tenantScope: 'org_beta', actorPersona: 'member_alpha' },
    ],
    nextTarget: {
      targetSurfaceKey: `${origin}|http|/api/v1/org-beta/exports/download`,
      surface: 'http',
      serviceOrigin: origin,
      endpoint: '/api/v1/org-beta/exports/download',
      method: 'GET',
      hypothesisClass: 'dual_tenant_abac',
      goalSummary: 'Follow derived webhook artifact handle to read foreign org_beta records.',
    },
    feasibilityProb: 0.85,
    terminalImpactWeight: 9,
    surfaceNovelty: 1.2,
    attemptsOnBranch: 0,
    consecutiveFailedAttempts: 0,
    createdWave: 1,
    lastUpdatedWave: 1,
  }
  const schedBuilt = buildHopCheckpointBrief(sampleBranch, 6.75)
  assert.equal(schedBuilt.brief.schema, ledgerBrief.schema)
  assert.equal(schedBuilt.brief.doNotRediscover, ledgerBrief.doNotRediscover)

  // Dispatch plan with checkpointBrief + checkpointJson and persist via ExecReconPlanner.
  const execution1 = new Execution(storage)
  const plan = dispatchInvestigations([{
    hypothesis: 'Pivot from Hop 3 artifact handle to foreign org_beta export download',
    origins: [origin],
    capabilities: ['http'],
    parentEvidenceIds: ['ev-seed-1'],
    skills: ['chain-primitives'],
    priority: 90,
    checkpointBrief: ledgerBrief,
    checkpointJson: JSON.stringify(ledgerBrief),
  }], { approvedOrigins: [origin] })
  assert.equal(plan.plan.length, 1)
  assert.equal(plan.plan[0]!.checkpointCapId, cap3)

  const planner1 = (execution1 as unknown as { reconPlanner: { persistDispatchPlan: Function; assignmentBriefForStep: Function } }).reconPlanner
  const counts = planner1.persistDispatchPlan(run, plan, new Set(['ev-seed-1']))
  assert.equal(counts.enqueued, 1)

  const persistedSteps = storage.listChainSteps(runId, run.goalRevision)
  const step = persistedSteps[persistedSteps.length - 1]!
  assert.equal(extractCheckpointCapIdFromStep(step), cap3, 'checkpointCapId must be persisted on ChainStep without schema migration')
  assert.ok(step.skills.includes(`${CHECKPOINT_CAP_SKILL_PREFIX}${cap3}`))

  // Simulate process restart: close Store, then open a brand-new Store & Execution against the same
  // SQLite dir (empty in-memory maps, empty parentChainHops!) and confirm assignmentBriefForStep
  // hydrates the full <= 2 KB HopCheckpointBrief from SQLite CapabilityLedger!
  storage.close()
  const restartedStore = new Store(dir)
  t.after(() => restartedStore.close())
  const execution2 = new Execution(restartedStore)
  const planner2 = (execution2 as unknown as { reconPlanner: { assignmentBriefForStep: Function } }).reconPlanner
  const reloadedRun = restartedStore.run(runId)
  const reloadedStep = restartedStore.listChainSteps(runId, reloadedRun.goalRevision).find(s => s.id === step.id)!

  const briefText = planner2.assignmentBriefForStep({
    run: reloadedRun,
    step: reloadedStep,
    targetOrigins: [origin],
    personas: [{ handle: 'member_alpha', roleLabel: 'member (org_alpha)' }],
    parentFacts: [],
    confirmed: [],
    detLeads: [],
    maxTurns: 12,
  }) as string | undefined
  assert.ok(briefText, 'assignmentBriefForStep must render a brief')
  const parsedBrief = JSON.parse(briefText) as { hopCheckpoint?: { schema?: string; capabilityHandles?: string[]; verifiedHops?: unknown[]; doNotRediscover?: boolean } }
  assert.ok(parsedBrief.hopCheckpoint, 'restarted assignmentBriefForStep must include hopCheckpoint hydrated from SQLite CapabilityLedger')
  assert.equal(parsedBrief.hopCheckpoint.schema, 'v8.hop_checkpoint.v1')
  assert.equal(parsedBrief.hopCheckpoint.doNotRediscover, true)
  assert.ok(parsedBrief.hopCheckpoint.capabilityHandles?.includes(cap3), 'checkpoint must retain cap3 even though it contains "artifact"')
  assert.ok((parsedBrief.hopCheckpoint.verifiedHops?.length ?? 0) >= 3, 'checkpoint must preserve full multi-hop lineage')
  const cpBytes = Buffer.byteLength(JSON.stringify(parsedBrief.hopCheckpoint), 'utf8')
  assert.ok(cpBytes > 480, `hopCheckpoint (${cpBytes} B) must not be truncated to legacy 480 B cap`)
  assert.ok(cpBytes <= DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES, `hopCheckpoint (${cpBytes} B) must remain <= 2048 B`)

  // Dead Execution.evaluateFrontierProgressForRound must be deleted and execution.ts < 6,000 LOC.
  assert.equal('evaluateFrontierProgressForRound' in Execution.prototype, false)
  const execLoc = readFileSync(join(REPO_ROOT, 'src/server/execution.ts'), 'utf8').split('\n').length
  assert.ok(execLoc < 6000, `src/server/execution.ts must stay < 6,000 LOC, got ${execLoc}`)
})

// ============================================================================
// 2. Deliverable 2: Default evaluateV8OracleFamily() Dispatch & No Circular Hack
// ============================================================================

test('A1.2: proof-receipt.ts has zero circular createRequire/loadCompositeModule/verifyReceiptUnified and composite-receipt.ts dispatches evaluateV8OracleFamily by default (<= 750 LOC)', () => {
  const proofSrc = readFileSync(join(REPO_ROOT, 'src/server/proof-receipt.ts'), 'utf8')
  assert.equal(proofSrc.includes('createRequire'), false, 'proof-receipt.ts must not use createRequire')
  assert.equal(proofSrc.includes('loadCompositeModule'), false, 'loadCompositeModule hack must be deleted')
  assert.equal(proofSrc.includes('verifyReceiptUnified'), false, 'unused verifyReceiptUnified must be deleted')
  assert.equal(proofSrc.includes('./composite-receipt.ts'), false, 'proof-receipt.ts must not import composite-receipt.ts')

  const compLoc = readFileSync(join(REPO_ROOT, 'src/server/composite-receipt.ts'), 'utf8').split('\n').length
  assert.ok(compLoc <= 750, `src/server/composite-receipt.ts must stay <= 750 LOC, got ${compLoc}`)

  // (a) Default evaluateV8OracleFamily() dispatch via terminalImpact.oracleInput (economic_conservation)
  const cap = 'cap:hop_1:refund_tok'
  const econEntries = [
    makeSignedEntry('ex-base', { arm: 'control', method: 'GET', pathAndQuery: '/api/orders/ord-1', status: 200, timestampMs: 1000, json: { paid: 100, refunded: 0 } }),
    makeSignedEntry('ex-ref1', { arm: 'probe', method: 'POST', pathAndQuery: '/api/orders/ord-1/refund', status: 200, timestampMs: 1100, emittedCapabilities: [cap], json: { refunded: 80 } }),
    makeSignedEntry('ex-ref2', { arm: 'probe', method: 'POST', pathAndQuery: '/api/orders/ord-1/refund', status: 200, timestampMs: 1200, consumedCapabilities: [cap], json: { refunded: 80 } }),
    makeSignedEntry('ex-final', { arm: 'control', method: 'GET', pathAndQuery: '/api/orders/ord-1', status: 200, timestampMs: 1300, json: { paid: 100, refunded: 160 } }),
  ]
  const econTranscript: HostSignedTranscript = { entries: econEntries }
  const mkRec = (e: HostTranscriptEntry) => ({ id: e.exchangeId, hostSignature: e.hostSignature!, timestampMs: e.timestampMs!, status: e.step.status })

  const econBase = {
    chainId: 'chain-a1-econ',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/api/orders/ord-1/refund' }, exchangeIds: ['ex-ref1'], producedCapabilities: [cap], claimedDelta: 'Issued first partial refund.' },
      { hopId: 'hop_2', surface: 'http', target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/api/orders/ord-1/refund' }, exchangeIds: ['ex-ref2'], consumedCapabilities: [cap], claimedDelta: 'Replayed second refund exceeding paid amount.' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    replayMode: 'fresh_clean_replay',
  }

  // Conserved ledger (50 + 40 <= 100) MUST fail closed via default evaluateV8OracleFamily('economic_conservation')!
  const econDenied = verifyCompositeReceipt({
    ...econBase,
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: 'Attempted over-refund across two partial refund requests.',
      terminalExchangeId: 'ex-ref2',
      oracleInput: {
        equation: 'over_refund',
        baselineReadback: mkRec(econEntries[0]!),
        actions: [mkRec(econEntries[1]!), mkRec(econEntries[2]!)],
        finalReadback: mkRec(econEntries[3]!),
        paidAmount: 100,
        refundedAmounts: [50, 40],
      },
    },
  }, econTranscript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(econDenied.confirmed, false)
  assert.equal(econDenied.failedStage, 'terminal_impact')
  assert.equal(econDenied.rejectedBy, 'v8_oracle_economic_conservation')
  assert.match(econDenied.reason, /refund_ledger_conserved/)

  // Over-refund (80 + 80 > 100) MUST confirm via default evaluateV8OracleFamily('economic_conservation')!
  const econConfirmed = verifyCompositeReceipt({
    ...econBase,
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: 'Confirmed over-refund violation: 160 refunded on 100 paid order.',
      terminalExchangeId: 'ex-ref2',
      oracleInput: {
        equation: 'over_refund',
        baselineReadback: mkRec(econEntries[0]!),
        actions: [mkRec(econEntries[1]!), mkRec(econEntries[2]!)],
        finalReadback: mkRec(econEntries[3]!),
        paidAmount: 100,
        refundedAmounts: [80, 80],
      },
    },
  }, econTranscript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(econConfirmed.confirmed, true, econConfirmed.reason)

  // (b) Default transcript-synthesized evaluateV8OracleFamily('cross_surface_pivot') rejects single-surface chains
  //     and confirms true multi-surface chains (e.g. graphql -> http) with denied pre-chain control!
  const pivotCap = 'cap:hop_1:pivot_tok'
  const pivotTranscript: HostSignedTranscript = {
    entries: [
      makeSignedEntry('ex-pctrl', { arm: 'control', method: 'GET', pathAndQuery: '/api/admin/audit', status: 403, timestampMs: 900 }),
      makeSignedEntry('ex-p1', { arm: 'probe', method: 'POST', pathAndQuery: '/graphql', status: 200, timestampMs: 1000, emittedCapabilities: [pivotCap], json: { data: { token: 'opaque' } } }),
      makeSignedEntry('ex-p2', { arm: 'probe', method: 'GET', pathAndQuery: '/api/admin/audit', status: 200, timestampMs: 1200, consumedCapabilities: [pivotCap], json: { tenantId: 'org_b', auditRows: [{ id: 1 }] } }),
    ],
  }
  const singleSurfaceFail = verifyCompositeReceipt({
    chainId: 'chain-a1-pivot-single',
    terminalVulnClass: 'cross_surface_pivot',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/graphql' }, exchangeIds: ['ex-p1'], producedCapabilities: [pivotCap], claimedDelta: 'Obtained pivot handle on HTTP.' },
      { hopId: 'hop_2', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/admin/audit' }, exchangeIds: ['ex-p2'], consumedCapabilities: [pivotCap], claimedDelta: 'Read admin audit on HTTP.' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: pivotCap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: 'Claimed cross-surface pivot on single HTTP surface.',
      terminalExchangeId: 'ex-p2',
      preChainControlExchangeIds: ['ex-pctrl'],
    },
    replayMode: 'fresh_clean_replay',
  }, pivotTranscript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(singleSurfaceFail.confirmed, false)
  assert.equal(singleSurfaceFail.rejectedBy, 'v8_oracle_cross_surface_pivot')
  assert.match(singleSurfaceFail.reason, /single_surface_not_cross_surface_pivot/)

  const multiSurfacePass = verifyCompositeReceipt({
    chainId: 'chain-a1-pivot-multi',
    terminalVulnClass: 'cross_surface_pivot',
    hops: [
      { hopId: 'hop_1', surface: 'graphql', target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/graphql' }, exchangeIds: ['ex-p1'], producedCapabilities: [pivotCap], claimedDelta: 'Obtained pivot handle via GraphQL mutation.' },
      { hopId: 'hop_2', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/admin/audit' }, exchangeIds: ['ex-p2'], consumedCapabilities: [pivotCap], claimedDelta: 'Read restricted org_b admin audit via HTTP.' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: pivotCap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: 'Cross-surface GraphQL-to-HTTP pivot exposed restricted org_b audit records.',
      terminalExchangeId: 'ex-p2',
      preChainControlExchangeIds: ['ex-pctrl'],
    },
    replayMode: 'fresh_clean_replay',
  }, pivotTranscript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(multiSurfacePass.confirmed, true, multiSurfacePass.reason)
})

// ============================================================================
// 3. Deliverable 3: Unified runAgentScriptProof & v8 Composite Patch Retest
// ============================================================================

test('A1.3: runV8AgentScriptProof is collapsed into unified runAgentScriptProof (zero monkey-patch) and retestPersistedAgentScript handles v8 CompositeProofReceipt', async (t) => {
  // Exact same function reference, zero monkey-patching in exec-verify.ts or agent-script-proof.ts!
  assert.equal(runV8AgentScriptProof, runAgentScriptProof)
  const execVerifySrc = readFileSync(join(REPO_ROOT, 'src/server/exec-verify.ts'), 'utf8')
  const agentProofSrc = readFileSync(join(REPO_ROOT, 'src/server/agent-script-proof.ts'), 'utf8')
  assert.equal(execVerifySrc.includes('server.verifyComposite ='), false, 'exec-verify.ts must not monkey-patch server.verifyComposite')
  assert.equal(agentProofSrc.includes('server.verifyComposite ='), false, 'agent-script-proof.ts must not monkey-patch server.verifyComposite')

  // Live loopback target toggleable between vulnerable and patched.
  let patched = false
  const rawSalt = 's_a1_retest_signing_salt_9876543210fedcba'
  const srv = createServer((req, res) => {
    const auth = req.headers.authorization ?? ''
    if (req.url === '/api/meta' && auth === 'Bearer tok_member_a') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ signingSalt: rawSalt }))
      return
    }
    if (req.url === '/api/vault/export') {
      const m = /^Bearer\s+([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(auth)
      if (!patched && m) {
        const expected = createHmac('sha256', rawSalt).update(`${m[1]}.${m[2]}`, 'utf8').digest('base64url')
        if (expected === m[3]) {
          res.writeHead(200, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ tenantId: 'org_victim', records: [{ id: 'v1', balanceCents: 99900 }] }))
          return
        }
      }
      res.writeHead(403, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'forbidden' }))
      return
    }
    res.writeHead(404)
    res.end()
  })
  srv.listen(0, '127.0.0.1')
  await once(srv, 'listening')
  t.after(() => srv.close())
  const addr = srv.address()
  assert.ok(addr && typeof addr !== 'string')
  const origin = `http://127.0.0.1:${addr.port}`

  const persona: ResolvedPersona = {
    id: 'p-member-a',
    handle: 'member_a',
    roleLabel: 'member (org_a)',
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: null,
    secret: 'tok_member_a',
    canaryMarkers: [],
  }
  const grant: Grant = {
    canRead: (url) => { try { return new URL(url).origin === origin } catch { return false } },
    audit: () => undefined,
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    personas: new Map([[persona.handle, persona]]),
  }
  const broker = new RequestBroker()

  const backend: WorkerBackend = {
    async run() { return { stdout: '', stderr: '', exitCode: 0, outputs: {}, timedOut: false } },
    async verifyStaticAst() { return { findings: [], errors: [], durationMs: 1 } as never },
    async openSession(_id: string, _signal: AbortSignal, opts?: WorkerSessionOptions): Promise<WorkerSession> {
      const mount = opts?.rpcMountDir ?? ''
      const socketPath = join(mount, VERIFY_RPC_SOCKET_NAME)
      const token = readFileSync(join(mount, VERIFY_RPC_TOKEN_NAME), 'utf8').trim()
      return {
        async exec() { return { stdout: '', stderr: '', exitCode: 0, outputs: {}, timedOut: false } },
        async stage(name: string) { return name },
        async analyze() { return { stdout: '', stderr: '', exitCode: 0, outputs: {}, timedOut: false } },
        async sast() { return {} as never },
        async runScript() { return { runtime: 'node' as const, stdout: '', stderr: '', exitCode: 0, durationMs: 1, timedOut: false } },
        async verifyStaticAst() { return { findings: [], errors: [], durationMs: 1 } as never },
        async verifyScript(req: VerifyScriptRequest): Promise<VerifyScriptResult> {
          const rpc = (op: string, args: Record<string, unknown>) => rpcCall(socketPath, token, req.nonce, op, args)
          const ctrl = await rpc('http.send', { origin, method: 'GET', path: '/api/vault/export', persona: 'member_a', sessionGroupRole: 'control' })
          const ctrlId = (ctrl.result as { exchangeId: string }).exchangeId
          const h1 = await rpc('http.send', { origin, method: 'GET', path: '/api/meta', persona: 'member_a', sessionGroupRole: 'probe' })
          const h1Id = (h1.result as { exchangeId: string }).exchangeId
          const sealed = await rpc('capability.seal', { exchangeId: h1Id, hopReceiptId: 'r1', slot: 'salt', jsonPath: 'signingSalt', kind: 'signing_salt', allowedOrigins: [origin] })
          const saltHandle = (sealed.result as { handle: string }).handle
          const minted = await rpc('crypto.jwtSign', { secretHandle: saltHandle, claims: { sub: 'member_a', scope: 'export' }, alg: 'HS256', hopReceiptId: 'r2', slot: 'jwt', allowedOrigins: [origin] })
          const mintedObj = minted.result as { exchangeId: string; derivedHandle: string }
          const h3 = await rpc('http.send', { origin, method: 'GET', path: '/api/vault/export', capability: { handle: mintedObj.derivedHandle, target: 'bearer' }, sessionGroupRole: 'probe' })
          const h3Id = (h3.result as { exchangeId: string }).exchangeId

          const compositeReceipt = {
            chainId: 'chain-a1-retest-composite',
            terminalVulnClass: 'cryptographic_scope_replay',
            replayMode: 'fresh_clean_replay',
            hops: [
              { hopId: 'hop_1', surface: 'http', target: { origin, method: 'GET', pathAndQuery: '/api/meta' }, exchangeIds: [h1Id], producedCapabilities: [saltHandle], claimedDelta: 'Leaked signing salt handle.' },
              { hopId: 'hop_2', surface: 'http', target: { origin, method: 'POST', pathAndQuery: '/crypto/jwt/HS256' }, exchangeIds: [mintedObj.exchangeId], consumedCapabilities: [saltHandle], producedCapabilities: [mintedObj.derivedHandle], claimedDelta: 'Minted HS256 JWT handle.' },
              { hopId: 'hop_3', surface: 'http', target: { origin, method: 'GET', pathAndQuery: '/api/vault/export' }, exchangeIds: [h3Id], consumedCapabilities: [mintedObj.derivedHandle], claimedDelta: 'Read foreign org_victim vault export.' },
            ],
            causalEdges: [
              { kind: 'derived_crypto_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sourceCapabilityId: saltHandle, derivedCapabilityId: mintedObj.derivedHandle, alg: 'HS256' },
              { kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_3', capabilityHandle: mintedObj.derivedHandle },
            ],
            terminalImpact: {
              terminalHopId: 'hop_3',
              summary: 'Derived HS256 JWT bypassed authorization to read foreign org_victim vault export.',
              terminalExchangeId: h3Id,
              preChainControlExchangeIds: [ctrlId],
            },
          }
          const verified = await rpc('composite.verify', { receipt: compositeReceipt })
          const verObj = verified.result as { confirmed: boolean; verificationId?: string }
          return {
            runtime: req.runtime,
            result: {
              sdk: 'kovo_verify.ts',
              title: 'Composite JWT scope replay',
              claims: verObj.verificationId ? [{ kind: 'composite_receipt', verificationId: verObj.verificationId, chainId: compositeReceipt.chainId, terminalVulnClass: compositeReceipt.terminalVulnClass, exchangeIds: [ctrlId, h1Id, mintedObj.exchangeId, h3Id] }] : [],
            },
            stdout: '',
            stderr: '',
            exitCode: 0,
            durationMs: 10,
            timedOut: false,
          }
        },
        async close() {},
      }
    },
  }

  const script = '// synthetic composite proof script'
  const envelope = {
    kind: 'agent_script' as const,
    runtime: 'ts' as const,
    script,
    scriptSha256: createHash('sha256').update(script).digest('hex'),
    verdict: 'confirmed' as const,
    exchangeIds: ['ex-1'],
    vulnClass: 'cryptographic_scope_replay',
    transcriptDigests: [],
    confirmedAt: Date.now(),
  }

  // (a) Unpatched target -> retestPersistedAgentScript reproduces the multi-hop CompositeProofReceipt!
  const unpatchedRetest = await retestPersistedAgentScript(envelope, {
    spec: { origin, agentScript: envelope },
    origin,
    broker,
    grant,
    backend,
    runId: 'a1-retest-unpatched',
    assignmentId: 'a1-retest-1',
    signal: new AbortController().signal,
    compositeVerifyOptions: { attackerPersonas: ['member_a'] },
  })
  assert.equal(unpatchedRetest.verdict, 'reproduced', unpatchedRetest.replay.outcome.reason ?? 'expected reproduced')
  assert.equal(unpatchedRetest.replay.verdict, 'confirmed')
  assert.ok((unpatchedRetest.replay.evidencePayload as Record<string, unknown>).compositeReceipt)

  // (b) Patched target -> retestPersistedAgentScript detects fix cleanly!
  patched = true
  const patchedRetest = await retestPersistedAgentScript(envelope, {
    spec: { origin, agentScript: envelope },
    origin,
    broker,
    grant,
    backend,
    runId: 'a1-retest-patched',
    assignmentId: 'a1-retest-2',
    signal: new AbortController().signal,
    compositeVerifyOptions: { attackerPersonas: ['member_a'] },
  })
  assert.equal(patchedRetest.verdict, 'fixed', patchedRetest.replay.outcome.reason ?? 'expected fixed')
  assert.equal(patchedRetest.replay.verdict, 'dismissed')
})
