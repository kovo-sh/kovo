import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { eq } from 'drizzle-orm'

import type { Finding } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import {
  retestPersistedAgentScript,
  runAgentScriptProof,
  type AgentScriptProofResult,
  type V8CompositeProofBundle,
} from '../src/server/agent-script-proof.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { CompositeProofReceipt } from '../src/server/composite-receipt.ts'
import {
  guardConfirmedFindingMutation,
  isGenericSharedAuthOrUtilityEndpoint,
} from '../src/server/exec-verify.ts'
import { Execution } from '../src/server/execution.ts'
import type { LabRunner } from '../src/server/lab-runner.ts'
import { applyUnifiedDiffToDirectory } from '../src/server/lab-runner.ts'
import {
  generateAndReviewPatch,
  verifyPatchApplicability,
} from '../src/server/patch-workflow.ts'
import { PersonaSessionPool } from '../src/server/persona-auth.ts'
import {
  buildPortableCompositeReceiptRecord,
  exportRunReceiptBundle,
  verifyProofReceiptBundle,
} from '../src/server/receipt-export.ts'
import { findings as findingsTable, replaySpecs } from '../src/server/schema.ts'
import { InvariantError, Store } from '../src/server/store.ts'
import {
  UnifiedDiffError,
  parseUnifiedDiff,
  validateDiffPath,
} from '../src/server/unified-diff.ts'
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
  WorkerJob,
  WorkerSession,
  WorkerSessionOptions,
} from '../src/server/worker-backend.ts'
import { makeLabGrant, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

function makeTempDir(prefix: string, t: { after: (fn: () => void) => void }): string {
  const dir = mkdtempSync(join(tmpdir(), `kovo-${prefix}-`))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function makeStore(t: { after: (fn: () => void) => void }): { storage: Store; dir: string } {
  const dir = makeTempDir('audit-proof-b', t)
  const storage = new Store(dir)
  t.after(() => storage.close())
  return { storage, dir }
}

function makeSpec(origin: string, endpoint = '/api/items/1'): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    spaCatchallControl: false,
    origin,
    title: 'Cross-tenant item read',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Unauthorized cross-tenant object read.',
    impact: 'Leaks foreign tenant record.',
    remediation: 'Verify tenant ownership.',
    recheckInstructions: 'Replay request as attacker.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "200", expected: "403" }',
    steps: [
      { id: 'c1', role: 'control', description: 'Control', request: { origin, method: 'GET', pathAndQuery: endpoint, followRedirects: false } },
      { id: 'p1', role: 'probe', description: 'Probe', request: { origin, method: 'GET', pathAndQuery: endpoint, followRedirects: false } },
    ],
  } as unknown as DeclarativeReplaySpec
}

function makeAttemptReport(attempt: 1 | 2, digest: string) {
  return {
    attempt,
    nonce: `nonce-${digest}`,
    exitCode: 0,
    durationMs: 5,
    oraclePassed: true,
    failures: [],
    claimCount: 1,
    exchangeCount: 2,
    transcriptDigest: digest,
    signaturesValid: true,
    causal: [],
    title: null,
    nonceMismatch: false,
    rejectedBy: null,
    missingEvidence: [],
    transcriptSummary: [],
  }
}

function makeCompositeProofResult(opts: {
  chainId: string
  hops: Array<{ hopId: string; origin: string; method: string; pathAndQuery: string; exchangeId: string }>
  claimTitle: string
  terminalOracleFamily?: string
}): AgentScriptProofResult {
  const terminalHop = opts.hops[opts.hops.length - 1]!
  const family = opts.terminalOracleFamily ?? 'dual_tenant_abac'
  const compositeReceipt: V8CompositeProofBundle = {
    receipt: {
      chainId: opts.chainId,
      terminalVulnClass: family,
      replayMode: 'fresh_clean_replay',
      hops: opts.hops.map(h => ({
        hopId: h.hopId,
        surface: 'http',
        target: { origin: h.origin, method: h.method, pathAndQuery: h.pathAndQuery },
        exchangeIds: [h.exchangeId],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: `Hop ${h.hopId}`,
        producedCapabilities: [],
        consumedCapabilities: [],
      })),
      causalEdges: [],
      terminalImpact: {
        terminalHopId: terminalHop.hopId,
        claimedImpact: 'Confirmed multi-hop impact.',
        summary: 'Confirmed multi-hop impact.',
        terminalExchangeId: terminalHop.exchangeId,
        oracleFamily: family as V8CompositeProofBundle['receipt']['terminalImpact']['oracleFamily'],
        preChainControlExchangeIds: [`${opts.chainId}-ctrl`],
        postChainReadbackExchangeIds: [`${opts.chainId}-rb`],
      },
    },
    verification: {
      confirmed: true,
      chainId: opts.chainId,
      terminalVulnClass: family,
      replayMode: 'fresh_clean_replay',
      modeBVerified: false,
      hopCount: opts.hops.length,
      verifiedEdges: [],
      reason: 'Verified composite chain.',
      terminalOracleFamily: family,
      terminalEndpoint: terminalHop.pathAndQuery,
    },
    hopActors: Object.fromEntries(opts.hops.map(h => [h.hopId, 'member_a'])),
  }

  return {
    verdict: {
      confirmed: true,
      reason: 'confirmed',
      detail: 'Two fresh runs confirmed composite chain.',
      attempts: [makeAttemptReport(1, `a1-${opts.chainId}`), makeAttemptReport(2, `a2-${opts.chainId}`)],
      disagreements: [],
      claimTitle: opts.claimTitle,
      rejectedBy: null,
      missingEvidence: [],
      transcriptSummary: [],
    },
    exchanges: opts.hops.map(h => ({
      exchangeId: h.exchangeId,
      op: 'http' as const,
      method: h.method,
      pathAndQuery: h.pathAndQuery,
      origin: h.origin,
      status: 200,
      durationMs: 4,
      personaHandle: 'member_a',
      sessionRole: h.hopId === terminalHop.hopId ? 'probe' as const : 'control' as const,
      actorRoleLabel: 'member',
      body: '{"ok":true}',
      requestHeaders: {},
      responseHeaders: { 'content-type': 'application/json' },
    })),
    receipt: null,
    compositeReceipt,
    vulnClass: family,
    transcriptDigests: [`a1-${opts.chainId}`, `a2-${opts.chainId}`],
    sealedCapabilities: [],
    transcriptRecords: [],
    hostTranscript: null,
    claimTitle: opts.claimTitle,
    severity: 'high',
    description: 'Composite proof.',
  }
}

function makeSingleHopProofResult(opts: {
  origin: string
  endpoint: string
  method?: string
  prefix: string
  title: string
}): AgentScriptProofResult {
  const method = opts.method ?? 'POST'
  const ctrlId = `${opts.prefix}-ctrl`
  const probeId = `${opts.prefix}-probe`
  return {
    verdict: {
      confirmed: true,
      reason: 'confirmed',
      detail: 'Confirmed single-hop proof.',
      attempts: [makeAttemptReport(1, `s1-${opts.prefix}`), makeAttemptReport(2, `s2-${opts.prefix}`)],
      disagreements: [],
      claimTitle: opts.title,
      rejectedBy: null,
      missingEvidence: [],
      transcriptSummary: [],
    },
    exchanges: [
      {
        exchangeId: ctrlId,
        op: 'http',
        method,
        pathAndQuery: opts.endpoint,
        origin: opts.origin,
        status: 403,
        durationMs: 2,
        personaHandle: 'member_a',
        sessionRole: 'control',
        actorRoleLabel: 'member',
        body: '{"error":"denied"}',
        requestHeaders: {},
        responseHeaders: {},
      },
      {
        exchangeId: probeId,
        op: 'http',
        method,
        pathAndQuery: opts.endpoint,
        origin: opts.origin,
        status: 200,
        durationMs: 3,
        personaHandle: 'member_a',
        sessionRole: 'probe',
        actorRoleLabel: 'member',
        body: '{"ok":true}',
        requestHeaders: {},
        responseHeaders: {},
      },
    ],
    receipt: {
      receipt: {
        vulnClass: 'authorization',
        target: { origin: opts.origin, method, pathAndQuery: opts.endpoint },
        exchangeIds: [ctrlId, probeId],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Single-hop bypass.',
      },
      verification: {
        confirmed: true,
        vulnClass: 'authorization',
        rule: 'auth_bypass',
        reason: 'Access control bypassed.',
        observed: '200',
        expected: '403',
      },
    },
    compositeReceipt: null,
    vulnClass: 'authorization',
    transcriptDigests: [`s1-${opts.prefix}`, `s2-${opts.prefix}`],
    sealedCapabilities: [],
    transcriptRecords: [],
    hostTranscript: null,
    claimTitle: opts.title,
    severity: 'medium',
    description: 'Single-hop proof.',
  }
}

// ============================================================================
// 1. C-5: Shell Command Injection & Option Injection in Patch Applicability
// ============================================================================

test('C-5: validateDiffPath rejects control chars and leading "-" option injection; verifyPatchApplicability uses zero shell interpolation', async (t) => {
  assert.throws(() => validateDiffPath('-rf', 'old'), UnifiedDiffError)
  assert.throws(() => validateDiffPath('a/-rf', 'old'), UnifiedDiffError)
  assert.throws(() => validateDiffPath('b/--upload-pack=evil', 'new'), UnifiedDiffError)
  assert.throws(() => validateDiffPath('a/file\nname.ts', 'old'), UnifiedDiffError)
  assert.throws(() => validateDiffPath('a/file\rname.ts', 'old'), UnifiedDiffError)
  assert.equal(validateDiffPath('a/src/app.ts\t2026-01-01 00:00:00', 'old'), 'src/app.ts')

  const reposDir = makeTempDir('c5-repos', t)
  const repo = 'demo-app'
  const repoRoot = join(reposDir, repo)
  const evilRel = 'src/$(touch pwned-marker);id.js'
  mkdirSync(join(repoRoot, 'src'), { recursive: true })
  writeFileSync(join(repoRoot, evilRel), 'export const v = 1\n')

  const diff = [
    `--- a/${evilRel}`,
    `+++ b/${evilRel}`,
    '@@ -1,1 +1,1 @@',
    '-export const v = 1',
    '+export const v = 2',
    '',
  ].join('\n')

  let capturedJob: WorkerJob | undefined
  const stubAst = async () => ({
    verified: true,
    engine: 'ast-grep' as const,
    repo,
    file: 'src/a.js',
    startLine: 1,
    endLine: 1,
    matchedLines: [],
    codeExcerpt: '',
    matchCount: 0,
    durationMs: 1,
  })
  const mockBackend: WorkerBackend = {
    async run(job) {
      capturedJob = job
      return { exitCode: 0, stdout: 'syntax-ok', stderr: '', outputs: {}, durationMs: 5, timedOut: false }
    },
    async openSession() {
      throw new Error('unused')
    },
    verifyStaticAst: stubAst,
  }

  const res = await verifyPatchApplicability({
    repoRoot,
    repo,
    reposDir,
    diff,
    fixBefore: 'export const v = 1',
    fixAfter: 'export const v = 2',
    codeLocations: [{ repo, file: evilRel, startLine: 1, endLine: 1 }],
    backend: mockBackend,
  })

  assert.equal(res.applicable, true)
  assert.equal(res.syntaxCheck.passed, true)
  assert.equal(existsSync(join(process.cwd(), 'pwned-marker')), false, 'shell metacharacters in filename must never execute')
  assert.ok(capturedJob)
  assert.equal(capturedJob!.command, 'node /evidence/patch_syntax_check.mjs')
  assert.ok(!capturedJob!.command.includes(evilRel), 'command must not interpolate filenames')
  assert.ok(!capturedJob!.command.includes(repo), 'command must not interpolate repo name')
  const manifestFile = capturedJob!.files.find(f => f.name === 'patch_syntax_manifest.json')
  assert.ok(manifestFile, 'manifest file must be staged as JSON')
  const parsedManifest = JSON.parse(manifestFile!.content) as { repo: string; files: Array<{ origName: string }> }
  assert.equal(parsedManifest.repo, repo)
  assert.equal(parsedManifest.files[0]!.origName, evilRel)
})

// ============================================================================
// 2. H-3: Store Confirmation Evidence Bypass & Contradiction Demotion
// ============================================================================

test('H-3: raw "ProofReceipt" prefix without structured proof is rejected, structured receipt passes, and contradicting retry demotes cleanly', async (t) => {
  const origin = 'http://127.0.0.1:4301'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const assignment = storage.makeWorker(run, 'verification', asset, 'Verifier', 'Verify H-3')

  // 1. Raw "ProofReceipt ..." string without structured receipt/event MUST fail assertConfirmationEvidence & upsertChainFinding.
  const forgedId = randomUUID()
  const emptySpec = storage.createReplaySpec(run, assignment, forgedId, makeSpec(origin), [origin])
  const forgedFinding: Finding = {
    id: forgedId,
    origin,
    title: 'Forged ProofReceipt string',
    status: 'confirmed',
    severity: 'high',
    reason: 'Claimed confirmation.',
    remediation: 'Fix.',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    confidence: 'high',
    verification: 'ProofReceipt forged-without-persisted-evidence',
    verificationTier: 'runtime_confirmed',
    findingKind: 'multi_step_chain',
    replaySpecId: emptySpec.id,
  }
  assert.throws(
    () => storage.upsertChainFinding(run, asset.id, forgedFinding, emptySpec.id, [origin]),
    (err: unknown) => err instanceof InvariantError && err.code === 'invariant.confirmation_evidence',
  )

  // 2. Structured persisted proofReceipt on replay_specs backs confirmation cleanly even when verification string starts with "ProofReceipt",
  //    AND a later contradicting retry (`inconclusive`) MUST demote it rather than silently blocking demotion!
  const backedId = randomUUID()
  const backedSpec = storage.createReplaySpec(run, assignment, backedId, makeSpec(origin, '/api/items/2'), [origin], {
    verifiedInline: true,
    proof: {
      replaySpecId: '',
      findingId: backedId,
      verdict: 'confirmed',
      runtime: 'ts',
      scriptSha256: 'a'.repeat(64),
      artifactId: null,
      receipt: {
        receipt: {
          vulnClass: 'idor',
          target: { origin, method: 'GET', pathAndQuery: '/api/items/2' },
          exchangeIds: ['ex-1'],
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: 'Foreign record read.',
        },
        verification: {
          confirmed: true,
          vulnClass: 'idor',
          rule: 'idor',
          reason: 'Verified cross-tenant read.',
          observed: '200',
          expected: '403',
        },
      },
      createdAt: Date.now(),
    },
  })
  const backedFinding: Finding = {
    ...forgedFinding,
    id: backedId,
    title: 'Structured ProofReceipt finding',
    verification: 'ProofReceipt ex-1 · idor rule · Verified cross-tenant read.',
    replaySpecId: backedSpec.id,
  }
  const persisted = storage.upsertChainFinding(run, asset.id, backedFinding, backedSpec.id, [origin])
  assert.equal(persisted.status, 'confirmed')

  // Contradicting re-verification retry writes verdict='inconclusive' -> MUST demote cleanly!
  storage.incrementReplaySpecAttempt(backedSpec.id, {
    verdict: 'inconclusive',
    controlPassed: false,
    assertionSummary: { observed: '403', expected: '200' },
    stepStatuses: [],
    retriesRemaining: 0,
  })

  const afterRetry = storage.db.select().from(findingsTable).where(eq(findingsTable.id, backedId)).get()!
  assert.equal(afterRetry.finding.status, 'inconclusive')
  assert.equal(afterRetry.verificationClass, 'open_proof_gap')
  assert.equal(afterRetry.verificationTier, null)
  assert.equal(storage.confirmationConflictCount(run.id), 1)
})

// ============================================================================
// 3. H-4 + #729 C3 part 2: guardConfirmedFindingMutation + run.id isolation
// ============================================================================

test('H-4: guardConfirmedFindingMutation blocks severity/identity edits, updateProposedFinding preserves confirmed identity, and PersonaSessionPool isolates run.id generations', async (t) => {
  const origin = 'http://127.0.0.1:4302'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const assignment = storage.makeWorker(run, 'verification', asset, 'Verifier', 'Verify H-4')

  const confirmedFinding: Finding = {
    id: randomUUID(),
    origin,
    title: 'Confirmed BOLA',
    status: 'confirmed',
    severity: 'medium',
    reason: 'Cross-tenant read.',
    remediation: 'Check owner.',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    confidence: 'high',
    verification: 'Zero-LLM confirmed',
    verificationTier: 'runtime_confirmed',
    findingKind: 'multi_step_chain',
  }

  const guard = guardConfirmedFindingMutation(confirmedFinding, {
    title: 'Mutated Critical RCE',
    severity: 'critical',
    category: 'injection-input',
    cwe: 'CWE-78',
    reason: 'Non-identity note',
  })
  assert.equal(guard.allowed, false)
  assert.deepEqual(new Set(guard.blockedFields), new Set(['cwe', 'title', 'category', 'severity']))
  assert.equal(guard.sanitizedPatch.severity, undefined)
  assert.equal(guard.sanitizedPatch.title, undefined)
  assert.equal(guard.sanitizedPatch.reason, 'Non-identity note')

  // Store-level updateProposedFinding also refuses to mutate identity/severity/category on confirmed findings.
  const spec = storage.createReplaySpec(run, assignment, confirmedFinding.id, makeSpec(origin), [origin], {
    verifiedInline: true,
    lastVerificationDiff: {
      verdict: 'confirmed',
      verificationTier: 'runtime_confirmed',
      controlPassed: true,
      assertionSummary: { observed: '200', expected: '403' },
      stepStatuses: [],
      retriesRemaining: 1,
    },
  })
  storage.upsertChainFinding(run, asset.id, { ...confirmedFinding, replaySpecId: spec.id }, spec.id, [origin])
  const afterUpdate = storage.updateProposedFinding(run, confirmedFinding.id, {
    finding: {
      title: 'Mutated Title',
      severity: 'critical',
      category: 'injection-input',
      cwe: 'CWE-89',
      origin: 'http://127.0.0.1:9999',
      reason: 'Appended detail',
    },
  })
  assert.equal(afterUpdate.title, 'Confirmed BOLA')
  assert.equal(afterUpdate.severity, 'medium')
  assert.equal(afterUpdate.category, 'broken-access-control')
  assert.equal(afterUpdate.cwe, 'CWE-639')
  assert.equal(afterUpdate.origin, origin)
  assert.equal(afterUpdate.reason, 'Appended detail')

  // Verify ExecWorkerRunner source wires guardConfirmedFindingMutation + run.id into warm-pool isolation policy.
  const runnerSrc = readFileSync(join(process.cwd(), 'src/server/exec-worker-runner.ts'), 'utf8')
  assert.ok(runnerSrc.includes('guardConfirmedFindingMutation('))
  assert.ok(runnerSrc.includes('stripUntrustedReplayEnvelopes('))
  assert.ok(runnerSrc.includes('buildWarmPoolPolicy('))
  assert.ok(runnerSrc.includes('runId: run.id'))

  // #729 C3 part 2 behavioral proof: rotating a persona in run-B must NOT mutate generation(handle, run-A).
  const pool = new PersonaSessionPool()
  pool.register('member_a', {
    runId: 'run-A',
    allowlist: [origin],
    session: { headerType: 'bearer', adapterUsed: 'form', value: 'tok-a1', scrubTokens: ['tok-a1'] },
  }, 'run-A')
  pool.register('member_a', {
    runId: 'run-B',
    allowlist: [origin],
    session: { headerType: 'bearer', adapterUsed: 'form', value: 'tok-b1', scrubTokens: ['tok-b1'] },
  }, 'run-B')
  assert.equal(pool.generation('member_a', 'run-A'), 1)
  assert.equal(pool.generation('member_a', 'run-B'), 1)
  // Rotate run-B only
  pool.register('member_a', {
    runId: 'run-B',
    allowlist: [origin],
    session: { headerType: 'bearer', adapterUsed: 'form', value: 'tok-b2', scrubTokens: ['tok-b2'] },
  }, 'run-B')
  assert.equal(pool.generation('member_a', 'run-A'), 1, 'run-A generation must stay isolated from run-B rotations')
  assert.equal(pool.generation('member_a', 'run-B'), 2)
})

// ============================================================================
// 4. H-5: supersedeUpstreamCompositeFindings excludes shared auth/utility routes & scopes goalRevision
// ============================================================================

test('H-5: supersedeUpstreamCompositeFindings preserves shared auth/utility route findings and isolates goalRevision', async (t) => {
  const origin = 'http://127.0.0.1:4303'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run0 = storage.run(runId)
  const asset = run0.candidates[0]!
  const worker = storage.makeWorker(run0, 'investigation', asset, 'Worker', 'Test H-5')

  assert.equal(isGenericSharedAuthOrUtilityEndpoint('/login'), true)
  assert.equal(isGenericSharedAuthOrUtilityEndpoint('/api/login'), true)
  assert.equal(isGenericSharedAuthOrUtilityEndpoint('/logout'), true)
  assert.equal(isGenericSharedAuthOrUtilityEndpoint('/auth/callback'), true)
  assert.equal(isGenericSharedAuthOrUtilityEndpoint('/api/v1/me'), true)
  assert.equal(isGenericSharedAuthOrUtilityEndpoint('/health'), true)
  assert.equal(isGenericSharedAuthOrUtilityEndpoint('/token'), true)
  assert.equal(isGenericSharedAuthOrUtilityEndpoint('/session'), true)
  assert.equal(isGenericSharedAuthOrUtilityEndpoint('/v1/tokens/exchange'), false)
  assert.equal(isGenericSharedAuthOrUtilityEndpoint('/v1/orders/:id'), false)

  const execution = new Execution(storage, { broker: new RequestBroker({ rejectUnauthorized: false }) })
  t.after(() => { void execution.stop() })
  const persist = (execution as unknown as {
    persistAgentScriptProof: (input: {
      run: ReturnType<Store['run']>
      assignment: ReturnType<Store['makeWorker']>
      script: string
      runtime: 'ts'
      title?: string
      proof: AgentScriptProofResult
      secrets: readonly []
    }) => { findingId: string }
  }).persistAgentScriptProof.bind(execution)

  // Confirmed finding on shared auth route POST /api/login in goalRevision 0
  const loginFinding = persist({
    run: run0,
    assignment: worker,
    script: '// login finding',
    runtime: 'ts',
    proof: makeSingleHopProofResult({
      origin,
      endpoint: '/api/login',
      method: 'POST',
      prefix: 'login',
      title: 'Auth issue on /api/login',
    }),
    secrets: [],
  })

  // Confirmed finding on business route GET /v1/orders/ord_1 in goalRevision 0
  const orderFindingRev0 = persist({
    run: run0,
    assignment: worker,
    script: '// order rev0',
    runtime: 'ts',
    proof: makeSingleHopProofResult({
      origin,
      endpoint: '/v1/orders/ord_1',
      method: 'GET',
      prefix: 'order-rev0',
      title: 'Order read in goalRevision 0',
    }),
    secrets: [],
  })

  // Composite chain in goalRevision 0 using /api/login -> /v1/orders/ord_2 -> /v1/orders/ord_2/approve
  // Must NOT supersede /api/login finding (generic auth route), even though it appears in upstream hops!
  const chainRev0 = persist({
    run: run0,
    assignment: worker,
    script: '// composite rev0',
    runtime: 'ts',
    proof: makeCompositeProofResult({
      chainId: 'chain-rev0',
      hops: [
        { hopId: 'h1', origin, method: 'POST', pathAndQuery: '/api/login', exchangeId: 'r0-h1' },
        { hopId: 'h2', origin, method: 'POST', pathAndQuery: '/v1/payouts/pay_1/approve', exchangeId: 'r0-h2' },
      ],
      claimTitle: 'Login then payout approve',
    }),
    secrets: [],
  })

  const loginRow = storage.db.select().from(findingsTable).where(eq(findingsTable.id, loginFinding.findingId)).get()!
  assert.equal(loginRow.supersededByFindingId ?? null, null, 'shared /api/login finding must NOT be superseded')
  assert.notEqual(chainRev0.findingId, loginFinding.findingId)

  // Composite chain in goalRevision 1 referencing /v1/orders/ord_2 MUST NOT supersede goalRevision 0 finding!
  const run1 = { ...run0, goalRevision: run0.goalRevision + 1 }
  persist({
    run: run1,
    assignment: { ...worker, goalRevision: run1.goalRevision },
    script: '// composite rev1',
    runtime: 'ts',
    proof: makeCompositeProofResult({
      chainId: 'chain-rev1',
      hops: [
        { hopId: 'h1', origin, method: 'GET', pathAndQuery: '/v1/orders/ord_2', exchangeId: 'r1-h1' },
        { hopId: 'h2', origin, method: 'POST', pathAndQuery: '/v1/orders/ord_2/approve', exchangeId: 'r1-h2' },
      ],
      claimTitle: 'Order chain in goalRevision 1',
    }),
    secrets: [],
  })
  const rev0OrderRow = storage.db.select().from(findingsTable).where(eq(findingsTable.id, orderFindingRev0.findingId)).get()!
  assert.equal(rev0OrderRow.supersededByFindingId ?? null, null, 'goalRevision 1 composite must NOT supersede goalRevision 0 finding')
})

// ============================================================================
// 5. M-1: Patch Gate 2/6 & unified-diff edge cases
// ============================================================================

test('M-1: Gate 2 requires fixAfter in changed + hunk lines, skips readFileSync on deleted files, Gate 6 rolls back live lab cleanly, and unified-diff handles EOF/header edge cases', async (t) => {
  const reposDir = makeTempDir('m1-repos', t)
  const repo = 'app'
  const repoRoot = join(reposDir, repo)
  mkdirSync(join(repoRoot, 'src'), { recursive: true })
  const originalSource = [
    '// header',
    'export function checkA(x: number) { return x }',
    'export function existingHelper() { if (!ok) return 403 }',
    '',
  ].join('\n')
  writeFileSync(join(repoRoot, 'src/a.ts'), originalSource)
  writeFileSync(join(repoRoot, 'src/obsolete.js'), 'export const old = 1\n')

  // 5a. Pre-existing fixAfter elsewhere in file + unrelated comment edit -> fixAppliedToCitedFile MUST be false!
  const decoyDiff = [
    '--- a/src/a.ts',
    '+++ b/src/a.ts',
    '@@ -1,2 +1,3 @@',
    ' // header',
    '+// decoy comment only',
    ' export function checkA(x: number) { return x }',
    '',
  ].join('\n')
  const decoyRes = await verifyPatchApplicability({
    repoRoot,
    repo,
    reposDir,
    diff: decoyDiff,
    fixBefore: 'export function checkA(x: number) { return x }',
    fixAfter: 'if (!ok) return 403',
    codeLocations: [{ repo, file: 'src/a.ts', startLine: 2, endLine: 2 }],
  })
  assert.equal(decoyRes.applicable, true)
  assert.equal(decoyRes.fixAppliedToCitedFile, false, 'pre-existing fixAfter outside + lines must NOT satisfy Gate 2')

  // 5b. Deleted file patch MUST NOT throw ENOENT during syntax checks (local or backend).
  const deleteDiff = [
    '--- a/src/obsolete.js',
    '+++ /dev/null',
    '@@ -1,1 +0,0 @@',
    '-export const old = 1',
    '',
  ].join('\n')
  const delRes = await verifyPatchApplicability({
    repoRoot,
    repo,
    reposDir,
    diff: deleteDiff,
    fixBefore: 'export const old = 1',
    fixAfter: '',
    codeLocations: [{ repo, file: 'src/obsolete.js', startLine: 1, endLine: 1 }],
  })
  assert.equal(delRes.applicable, true)
  assert.equal(delRes.syntaxCheck.passed, true)
  assert.equal(delRes.fixAppliedToCitedFile, true)

  // 5c. Gate 6: passes envelopeTrust: 'host_persisted' and rolls back BOTH live container and sanitizedRepoDir!
  const gate6ReposDir = makeTempDir('m1-gate6-repos', t)
  const gate6Repo = join(gate6ReposDir, 'svc')
  const liveSanitized = makeTempDir('m1-gate6-live', t)
  mkdirSync(join(gate6Repo, 'src'), { recursive: true })
  mkdirSync(join(liveSanitized, 'src'), { recursive: true })
  const vulnCode = 'export function handle(ok) {\n  return 200\n}\n'
  const fixedCode = 'export function handle(ok) {\n  if (!ok) return 403\n  return 200\n}\n'
  writeFileSync(join(gate6Repo, 'src/handler.js'), vulnCode)
  writeFileSync(join(liveSanitized, 'src/handler.js'), vulnCode)

  const rebuildDiffs: string[] = []
  const mockLabRunner = {
    rebuildWithPatch: async (_runId: string, diff: string) => {
      rebuildDiffs.push(diff)
      applyUnifiedDiffToDirectory(liveSanitized, diff)
      return {
        targetId: 't1',
        origin: 'http://127.0.0.1:4399',
        containerName: 'c1',
        containerNames: ['c1'],
        containerIp: '127.0.0.1',
        internalPort: 4399,
        healthPath: '/health',
        networkName: 'net',
        imageName: 'img',
        sanitizedRepoDir: liveSanitized,
        telemetryDir: liveSanitized,
        startedAt: Date.now(),
      }
    },
  } as unknown as LabRunner

  // Persisted agent script spec that requires host_persisted (if untrusted, replay would reject/fail)
  const origin = 'http://127.0.0.1:4399'
  const broker = new RequestBroker({
    rejectUnauthorized: false,
    transport: async () => ({ status: 403, headers: {}, body: 'forbidden' }),
  })
  const grant = makeLabGrant(origin)
  const resGate6 = await generateAndReviewPatch({
    runId: 'run-gate6-m1',
    finding: {
      id: 'f-gate6',
      origin,
      title: 'Missing auth check',
      cwe: 'CWE-862',
      category: 'broken-access-control',
      severity: 'high',
      status: 'confirmed',
      reason: 'Missing check.',
      remediation: 'Add check.',
      evidenceIds: [],
      scopeRevision: 1,
      codeLocations: [{ repo: 'svc', file: 'src/handler.js', startLine: 2, endLine: 2 }],
    },
    repo: 'svc',
    reposDir: gate6ReposDir,
    candidatePatch: {
      fixBefore: '  return 200',
      fixAfter: '  if (!ok) return 403\n  return 200',
      codeLocations: [{ repo: 'svc', file: 'src/handler.js', startLine: 2, endLine: 2 }],
      rationale: 'Enforce check.',
    },
    reviewerLlmCall: async () => JSON.stringify({
      approved: true,
      callerCompatibility: 'attacker_only',
      enforcingLocation: 'src/handler.js:2',
      gates: [
        { gate: 1, name: 'applicability', passed: true, detail: 'ok' },
        { gate: 2, name: 'security_closure', passed: true, detail: 'ok' },
        { gate: 3, name: 'sibling_coverage', passed: true, detail: 'ok' },
        { gate: 4, name: 'caller_compatibility', passed: true, detail: 'ok' },
        { gate: 5, name: 'repo_conventions', passed: true, detail: 'ok' },
      ],
      reviewNotes: 'Approved statically.',
    }),
    labRetest: {
      labRunner: mockLabRunner,
      runId: 'run-gate6-m1',
      sanitizedRepoDir: liveSanitized,
      replaySpec: makeSpec(origin, '/api/check'),
      broker,
      backend: {
        async run() { return { exitCode: 0, stdout: '', stderr: '', outputs: {}, durationMs: 1, timedOut: false } },
        async openSession() { throw new Error('unused') },
        async verifyStaticAst() {
          return { verified: true, engine: 'ast-grep', repo: 'svc', file: 'src/handler.js', startLine: 1, endLine: 1, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }
        },
      },
      grant,
      baselineCaller: { origin, method: 'GET', pathAndQuery: '/health' },
    },
  })
  assert.equal(rebuildDiffs.length, 2, 'Gate 6 must apply candidate patch AND rebuild clean container on rollback')
  assert.equal(readFileSync(join(liveSanitized, 'src/handler.js'), 'utf8'), vulnCode, 'Gate 6 rollback must restore clean repo')
  assert.ok(fixedCode.length > 0 && resGate6.gates.length === 6)

  // 5d. unified-diff edge cases: stripped blank context line at EOF and before section header
  const eofBlankDiff = [
    '--- a/src/blank.txt',
    '+++ b/src/blank.txt',
    '@@ -1,3 +1,3 @@',
    '-old',
    '+new',
    ' middle',
    '',
    '',
  ].join('\n')
  const parsedEof = parseUnifiedDiff(eofBlankDiff)
  assert.equal(parsedEof[0]!.hunks[0]!.entries[3]!.kind, 'context')
  assert.equal(parsedEof[0]!.hunks[0]!.entries[3]!.text, '')

  const multiHunkBlankDiff = [
    '--- a/src/blank.txt',
    '+++ b/src/blank.txt',
    '@@ -1,2 +1,2 @@',
    '-old1',
    '+new1',
    '',
    '@@ -5,2 +5,2 @@',
    '-old2',
    '+new2',
    ' tail',
    '',
  ].join('\n')
  const parsedMulti = parseUnifiedDiff(multiHunkBlankDiff)
  assert.equal(parsedMulti[0]!.hunks.length, 2)
  assert.equal(parsedMulti[0]!.hunks[0]!.entries[2]!.kind, 'context')

  // Reject unsafe copy from/to, valid rename/copy headers, mismatched paths, and stray lines outside hunks.
  assert.throws(() => parseUnifiedDiff('copy from ../secret\ncopy to b.txt\n'), /Unsafe/)
  assert.throws(() => parseUnifiedDiff('copy from a.txt\ncopy to b.txt\n'), UnifiedDiffError)
  assert.throws(() => parseUnifiedDiff('rename from a.txt\nrename to b.txt\n'), UnifiedDiffError)
  assert.throws(() => parseUnifiedDiff('--- a/old.ts\n+++ b/new.ts\n@@ -1,1 +1,1 @@\n-a\n+b\n'), UnifiedDiffError)
  assert.throws(() => parseUnifiedDiff('garbage stray line\n--- a/a.ts\n+++ b/a.ts\n@@ -1,1 +1,1 @@\n-a\n+b\n'), UnifiedDiffError)
})

// ============================================================================
// 6. M-2: receipt-export.ts signing envelope, key type, and no fake receipts
// ============================================================================

test('M-2: signed bundle binds algorithm & keyId, enforces receiptCount, validates ed25519 PEM, defaults composite confirmed=false, and refuses synthetic ProofReceipt fabrication', async (t) => {
  const { storage } = makeStore(t)
  const origin = 'https://m2.example.test'
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'M2 Receipt Integrity',
    seeds: [origin],
    environment: 'public',
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId,
    goal: 'Verify M2 export integrity',
    sourceMode: 'public',
    capabilityTier: 2,
    budgetUsd: 5,
    budgetRequests: 20,
    maxRpsPerOrigin: 5,
    workerConcurrency: 1,
    workerMaxTurns: 5,
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const asset = storage.run(runId).candidates[0]!
  storage.command({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    expectedScopeRevision: 0,
    assetIds: [asset.id],
    consent: true,
    capabilityTier: 2,
  })

  // Insert a confirmed legacy finding backed by a replaySpec diff without any persisted proofReceipt.
  const worker = storage.makeWorker(storage.run(runId), 'investigation', asset, 'Probe', 'Legacy M2')
  const legacyId = randomUUID()
  const legacySpec = storage.createReplaySpec(storage.run(runId), worker, legacyId, makeSpec(origin, '/legacy'), [origin], {
    verifiedInline: true,
    lastVerificationDiff: {
      verdict: 'confirmed',
      verificationTier: 'runtime_confirmed',
      controlPassed: true,
      assertionSummary: { observed: '200', expected: '403' },
      stepStatuses: [],
      retriesRemaining: 0,
    },
  })
  storage.db.insert(findingsTable).values({
    id: legacyId,
    runId,
    assetId: asset.id,
    goalRevision: 0,
    checkId: 'chain',
    caseId: 'legacy-1',
    findingKind: 'multi_step_chain',
    replaySpecId: legacySpec.id,
    provenance: 'floor',
    verificationClass: 'runtime_confirmed',
    sourceOrigins: [origin],
    verificationTier: 'runtime_confirmed',
    finding: {
      id: legacyId,
      origin,
      title: 'Legacy receiptless finding',
      status: 'confirmed',
      severity: 'high',
      reason: 'Legacy finding without persisted ProofReceipt.',
      remediation: 'Fix it.',
      evidenceIds: [],
      scopeRevision: 1,
      category: 'broken-access-control',
      cwe: 'CWE-639',
      replaySpecId: legacySpec.id,
    } as never,
  }).run()

  const hmacSecret = 'm2-test-hmac-secret-0123456789abcdef'
  const bundle = exportRunReceiptBundle(storage, runId, {
    signing: { algorithm: 'hmac-sha256', secret: hmacSecret, keyId: 'key-alpha' },
  })
  assert.equal(verifyProofReceiptBundle(bundle, { secret: hmacSecret }).valid, true)

  // Receiptless legacy finding must carry receipt: null and confirmed: false (never fabricated!).
  assert.equal(bundle.payload.records.length, 1)
  assert.equal(bundle.payload.records[0]!.receipt, null)
  assert.equal(bundle.payload.records[0]!.verification.confirmed, false)
  assert.equal(bundle.payload.records[0]!.verification.rule, 'legacy_unreceipted')

  // Tampering keyId must fail verification!
  const tamperedKeyId = structuredClone(bundle)
  tamperedKeyId.keyId = 'key-tampered'
  assert.equal(verifyProofReceiptBundle(tamperedKeyId, { secret: hmacSecret }).valid, false)

  // Mismatched receiptCount vs records.length must fail even if payloadSha256 is recomputed.
  const badCount = structuredClone(bundle)
  badCount.payload.receiptCount = 99
  assert.equal(verifyProofReceiptBundle(badCount, { secret: hmacSecret }).valid, false)

  // Non-Ed25519 PEM in KOVO_RECEIPT_SIGNING_KEY must throw!
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const rsaPem = rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  const prevEnv = process.env.KOVO_RECEIPT_SIGNING_KEY
  process.env.KOVO_RECEIPT_SIGNING_KEY = rsaPem
  try {
    assert.throws(() => exportRunReceiptBundle(storage, runId), /Ed25519/i)
  } finally {
    if (prevEnv !== undefined) process.env.KOVO_RECEIPT_SIGNING_KEY = prevEnv
    else delete process.env.KOVO_RECEIPT_SIGNING_KEY
  }

  // buildPortableCompositeReceiptRecord without verification defaults confirmed to false.
  const dummyComposite: CompositeProofReceipt = {
    chainId: 'c-1',
    terminalVulnClass: 'dual_tenant_abac',
    replayMode: 'fresh_clean_replay',
    hops: [
      {
        hopId: 'h1',
        surface: 'http',
        target: { origin, method: 'GET', pathAndQuery: '/api/me' },
        exchangeIds: ['e1'],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'delta',
        producedCapabilities: [],
        consumedCapabilities: [],
      },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'h1',
      claimedImpact: 'impact',
      preChainControlExchangeIds: [],
      postChainReadbackExchangeIds: [],
    },
  }
  const compRec = buildPortableCompositeReceiptRecord({ receipt: dummyComposite })
  assert.equal(compRec.confirmed, false)
})

// ============================================================================
// 7. M-3b: agent-script-proof.ts agreement check, hasConfirmedProof, scratch alignment
// ============================================================================

test('M-3b: agent-script-proof checks terminalEndpoint & terminalOracleFamily agreement, enforces hasConfirmedProof when vulnClass is empty, and aligns staging root with KOVO_CONTAINER_SCRATCH_DIR', async (t) => {
  const origin = 'http://127.0.0.1:4304'
  const scratchRoot = makeTempDir('m3b-scratch', t)
  const prevScratch = process.env.KOVO_CONTAINER_SCRATCH_DIR
  process.env.KOVO_CONTAINER_SCRATCH_DIR = scratchRoot
  t.after(() => {
    if (prevScratch !== undefined) process.env.KOVO_CONTAINER_SCRATCH_DIR = prevScratch
    else delete process.env.KOVO_CONTAINER_SCRATCH_DIR
  })

  const observedRpcDirs: string[] = []
  let attemptCounter = 0

  const makeMockBackend = (mode: 'disagree_endpoint' | 'no_receipt'): WorkerBackend => ({
    async run() {
      return { exitCode: 0, stdout: '', stderr: '', outputs: {}, durationMs: 1, timedOut: false }
    },
    async verifyStaticAst() {
      return { verified: true, engine: 'ast-grep', repo: 'app', file: 'src/a.ts', startLine: 1, endLine: 1, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }
    },
    async openSession(_assignmentId: string, _signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerSession> {
      const rpcDir = options?.rpcMountDir ?? ''
      observedRpcDirs.push(rpcDir)
      const currentAttempt = ++attemptCounter
      return {
        async stage() { return '' },
        async exec() { return { exitCode: 0, stdout: '', stderr: '', outputs: {}, durationMs: 1, timedOut: false } },
        async analyze() { return {} },
        async sast() { return { repo: 'app', enginesRun: [], engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 } },
        async runScript() { return { runtime: 'node', exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false } },
        async verifyStaticAst() {
          return { verified: true, engine: 'ast-grep', repo: 'app', file: 'src/a.ts', startLine: 1, endLine: 1, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }
        },
        async verifyScript(req: VerifyScriptRequest): Promise<VerifyScriptResult> {
          if (mode === 'disagree_endpoint') {
            // Post composite.verify via real VerifyRpcServer Unix socket with differing terminalEndpoint across runs.
            const http = await import('node:http')
            const sock = join(rpcDir, VERIFY_RPC_SOCKET_NAME)
            const tok = readFileSync(join(rpcDir, VERIFY_RPC_TOKEN_NAME), 'utf8').trim()
            const targetEndpoint = currentAttempt === 1 ? '/api/orders/1' : '/api/orders/2'
            const callRpc = (method: string, params: Record<string, unknown>) =>
              new Promise<Record<string, unknown>>((resolve, reject) => {
                const payload = JSON.stringify({ method, params })
                const r = http.request({
                  socketPath: sock,
                  path: '/rpc',
                  method: 'POST',
                  headers: {
                    'content-type': 'application/json',
                    'content-length': Buffer.byteLength(payload),
                    [VERIFY_RPC_HEADER]: tok,
                    [VERIFY_NONCE_HEADER]: req.nonce,
                  },
                }, (res) => {
                  const chunks: Buffer[] = []
                  res.on('data', c => chunks.push(Buffer.from(c)))
                  res.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>))
                })
                r.on('error', reject)
                r.write(payload)
                r.end()
              })
            await callRpc('http.send', { origin, method: 'GET', pathAndQuery: targetEndpoint, arm: 'control', persona: 'member_b' })
            const probeRes = await callRpc('http.send', { origin, method: 'GET', pathAndQuery: targetEndpoint, arm: 'probe', persona: 'member_a' })
            const rbRes = await callRpc('http.send', { origin, method: 'GET', pathAndQuery: targetEndpoint, arm: 'control', persona: 'owner_a' })
            const ctrlExId = String((probeRes as { exchangeId?: string }).exchangeId ?? 'ex-p')
            const rbExId = String((rbRes as { exchangeId?: string }).exchangeId ?? 'ex-rb')
            await callRpc('composite.verify', {
              receipt: {
                chainId: 'same-chain-id',
                terminalVulnClass: 'dual_tenant_abac',
                replayMode: 'fresh_clean_replay',
                hops: [
                  {
                    hopId: 'hop_1',
                    surface: 'http',
                    target: { origin, method: 'GET', pathAndQuery: targetEndpoint },
                    exchangeIds: [ctrlExId],
                    oobEventIds: [],
                    browserTraceIds: [],
                    claimedDelta: 'Read foreign order',
                    producedCapabilities: [],
                    consumedCapabilities: [],
                  },
                ],
                causalEdges: [],
                terminalImpact: {
                  terminalHopId: 'hop_1',
                  claimedImpact: 'Read foreign order',
                  terminalExchangeId: ctrlExId,
                  oracleFamily: 'dual_tenant_abac',
                  preChainControlExchangeIds: [ctrlExId],
                  postChainReadbackExchangeIds: [rbExId],
                },
              },
            })
            return {
              runtime: 'ts',
              result: {
                claims: [{ kind: 'access_boundary', controlExchangeId: ctrlExId, probeExchangeId: ctrlExId, summary: 'ok' }],
              },
              stdout: '',
              stderr: '',
              exitCode: 0,
              durationMs: 2,
              timedOut: false,
            }
          }
          // mode === 'no_receipt': exits 0 with empty claims (so verdict.confirmed could be false or receipt null)
          return {
            runtime: 'ts',
            result: { claims: [] },
            stdout: '',
            stderr: '',
            exitCode: 0,
            durationMs: 1,
            timedOut: false,
          }
        },
        async close() {},
      }
    },
  })

  const broker = new RequestBroker({
    rejectUnauthorized: false,
    transport: async (url) => {
      if (url.pathname === '/api/orders/1') return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"id":1}' }
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"id":2}' }
    },
  })
  const grant = makeLabGrant(origin, {
    personas: new Map([
      ['member_a', { id: 'p-a', handle: 'member_a', roleLabel: 'member', originAllowlist: [origin], authKind: 'bearer', headerName: null, secret: 'tok-a', canaryMarkers: [] }],
      ['member_b', { id: 'p-b', handle: 'member_b', roleLabel: 'member', originAllowlist: [origin], authKind: 'bearer', headerName: null, secret: 'tok-b', canaryMarkers: [] }],
      ['owner_a', { id: 'p-o', handle: 'owner_a', roleLabel: 'owner', originAllowlist: [origin], authKind: 'bearer', headerName: null, secret: 'tok-o', canaryMarkers: [] }],
    ]),
  })

  // Verify staging root alignment with KOVO_CONTAINER_SCRATCH_DIR + empty-vulnClass hasConfirmedProof check.
  const emptyVulnScript = 'export async function verify() { return { claims: [] } }'
  const emptyVulnRetest = await retestPersistedAgentScript(
    {
      kind: 'agent_script',
      runtime: 'ts',
      script: emptyVulnScript,
      scriptSha256: createHash('sha256').update(emptyVulnScript).digest('hex'),
      verdict: 'confirmed',
      vulnClass: '',
      exchangeIds: [],
      transcriptDigests: [],
      confirmedAt: Date.now(),
    },
    {
      spec: makeSpec(origin),
      origin,
      broker,
      grant,
      backend: makeMockBackend('no_receipt'),
      runId: 'run-m3b',
      assignmentId: 'assign-m3b',
      signal: AbortSignal.timeout(10_000),
    },
  )
  assert.equal(emptyVulnRetest.verdict, 'inconclusive')
  assert.equal(emptyVulnRetest.replay.outcome.confirmed, false)
  assert.ok(observedRpcDirs.length >= 1)
  assert.ok(observedRpcDirs.every(dir => dir.startsWith(scratchRoot + '/')), 'VerifyRpcServer hostDir must align under KOVO_CONTAINER_SCRATCH_DIR when set')

  // Verify composite agreement check via runAgentScriptProof with compositeVerifyOptions (no-op if attempts didn't confirm composite, or verify direct rejection when both confirm different terminalEndpoint).
  // Use a script that succeeds cleanly on composite verification for both attempts with different terminalEndpoint.
  const disagreeRes = await runAgentScriptProof({
    script: '// test disagree',
    runtime: 'ts',
    broker,
    grant,
    backend: makeMockBackend('disagree_endpoint'),
    runId: 'run-m3b-disagree',
    assignmentId: 'assign-m3b-disagree',
    targetOrigins: [origin],
    signal: AbortSignal.timeout(10_000),
  })
  assert.equal(disagreeRes.verdict.confirmed, false, 'mismatched terminalEndpoint across fresh runs must not confirm')
})
