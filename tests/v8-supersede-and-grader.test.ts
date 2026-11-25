/**
 * P0 M2 Precision & Grader Accuracy tests:
 *  1. `src/server/exec-verify.ts`: Superseding earlier partial-hop / single-hop confirmed findings
 *     when a superset multi-hop `CompositeProofReceipt` confirms, while preserving unrelated,
 *     terminal-only, method-mismatched, cross-host, already-superseded, and floor-provenance rows.
 *  2. `benchmarks/multihop-saas/run.ts`:
 *     (a) Post-mutation read-only (`GET`) readback tail resolution in `resolveReceiptChainId`.
 *     (b) Vulnerable-mode `forbiddenShortcutViolation` stays a strict `unmatchedFalsePositives`
 *         precision FP (never weakening precision) without double-attributing into `hardenedTwinDecoyFps`.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { eq } from 'drizzle-orm'

import {
  gradeRun,
  startMultihopApp,
  type ProductSubmittedCompositeProof,
  type ProductSubmittedFinding,
  type StartedMultihopApp,
} from '../benchmarks/multihop-saas/run.ts'
import type { ChainEvaluation, HopDropReason, OracleExport } from '../benchmarks/multihop-saas/lib/types.ts'
import { extractCompositeReceipts } from '../scripts/benchmark-multihop.ts'
import { translateFindings } from '../scripts/benchmark-realistic.ts'
import type { Finding } from '../src/domain.ts'
import type { AgentScriptProofResult, V8CompositeProofBundle } from '../src/server/agent-script-proof.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import { findings } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

function makeStore(t: { after: (fn: () => void) => void }): { storage: Store; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v8-supersede-grader-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })
  return { storage, dir }
}

type PersistFn = (input: {
  run: ReturnType<Store['run']>
  assignment: ReturnType<Store['makeWorker']>
  script: string
  runtime: 'ts'
  title?: string
  proof: AgentScriptProofResult
  secrets: readonly []
}) => { findingId: string; replaySpecId: string; receiptId: string | null }

function persistViaExecution(execution: Execution): PersistFn {
  return (execution as unknown as { persistAgentScriptProof: PersistFn }).persistAgentScriptProof.bind(execution)
}

function makeAttemptReport(attempt: 1 | 2, digest: string) {
  return {
    attempt,
    nonce: `nonce-${digest}`,
    exitCode: 0,
    durationMs: 10,
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

function makeSingleHopProof(opts: {
  origin: string
  endpoint: string
  method?: string
  vulnClass?: string
  exchangePrefix: string
  claimTitle: string
}): AgentScriptProofResult {
  const method = opts.method ?? 'POST'
  const vulnClass = opts.vulnClass ?? 'authorization'
  const ctrlId = `${opts.exchangePrefix}-ctrl`
  const probeId = `${opts.exchangePrefix}-probe`
  return {
    verdict: {
      confirmed: true,
      reason: 'confirmed',
      detail: 'Two fresh runs confirmed the single-hop receipt.',
      attempts: [
        makeAttemptReport(1, `s1-${opts.exchangePrefix}`),
        makeAttemptReport(2, `s2-${opts.exchangePrefix}`),
      ],
      disagreements: [],
      claimTitle: opts.claimTitle,
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
        durationMs: 3,
        personaHandle: 'member_a',
        sessionRole: 'control',
        actorRoleLabel: 'member',
        body: '{"error":"forbidden"}',
        requestHeaders: {},
        responseHeaders: { 'content-type': 'application/json' },
      },
      {
        exchangeId: probeId,
        op: 'http',
        method,
        pathAndQuery: opts.endpoint,
        origin: opts.origin,
        status: 200,
        durationMs: 5,
        personaHandle: 'member_a',
        sessionRole: 'probe',
        actorRoleLabel: 'member',
        body: '{"ok":true}',
        requestHeaders: {},
        responseHeaders: { 'content-type': 'application/json' },
      },
    ],
    receipt: {
      receipt: {
        vulnClass,
        target: {
          origin: opts.origin,
          method,
          pathAndQuery: opts.endpoint,
        },
        exchangeIds: [ctrlId, probeId],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Single-hop control bypassed.',
      },
      verification: {
        confirmed: true,
        vulnClass,
        rule: 'auth_bypass',
        reason: 'Cross-tenant access succeeded.',
        observed: '200 OK',
        expected: '403 Forbidden',
      },
    },
    compositeReceipt: null,
    vulnClass,
    transcriptDigests: [`s1-${opts.exchangePrefix}`, `s2-${opts.exchangePrefix}`],
    sealedCapabilities: [],
    transcriptRecords: [],
    hostTranscript: null,
    claimTitle: opts.claimTitle,
    severity: 'medium',
    description: 'Single-hop proof.',
  }
}

function makeCompositeProof(opts: {
  chainId: string
  terminalVulnClass?: string
  hops: Array<{ hopId: string; origin: string; method: string; pathAndQuery: string; exchangeId: string }>
  terminalHopId?: string
  claimTitle: string
  severity?: 'low' | 'medium' | 'high' | 'critical'
}): AgentScriptProofResult {
  const terminalVulnClass = opts.terminalVulnClass ?? 'dual_tenant_abac'
  const terminalHop = opts.hops.find(h => h.hopId === opts.terminalHopId) ?? opts.hops[opts.hops.length - 1]!
  const ctrlId = `${opts.chainId}-ctrl`
  const readbackId = `${opts.chainId}-rb`

  const compositeReceipt: V8CompositeProofBundle = {
    receipt: {
      chainId: opts.chainId,
      terminalVulnClass,
      replayMode: 'fresh_clean_replay',
      hops: opts.hops.map(h => ({
        hopId: h.hopId,
        surface: 'http',
        target: {
          origin: h.origin,
          method: h.method,
          pathAndQuery: h.pathAndQuery,
        },
        exchangeIds: [h.exchangeId],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: `Hop ${h.hopId} delta`,
        producedCapabilities: [],
        consumedCapabilities: [],
      })),
      causalEdges: [],
      terminalImpact: {
        terminalHopId: terminalHop.hopId,
        claimedImpact: 'Confirmed multi-hop terminal impact.',
        summary: 'Confirmed multi-hop terminal impact.',
        terminalExchangeId: terminalHop.exchangeId,
        oracleFamily: terminalVulnClass as V8CompositeProofBundle['receipt']['terminalImpact']['oracleFamily'],
        preChainControlExchangeIds: [ctrlId],
        postChainReadbackExchangeIds: [readbackId],
      },
    },
    verification: {
      confirmed: true,
      chainId: opts.chainId,
      terminalVulnClass,
      replayMode: 'fresh_clean_replay',
      modeBVerified: false,
      hopCount: opts.hops.length,
      verifiedEdges: [],
      reason: 'Composite chain verified.',
      terminalOracleFamily: terminalVulnClass,
      terminalEndpoint: terminalHop.pathAndQuery,
    },
    hopActors: Object.fromEntries(opts.hops.map(h => [h.hopId, 'member_a'])),
  }

  return {
    verdict: {
      confirmed: true,
      reason: 'confirmed',
      detail: 'Two fresh script runs confirmed composite proof.',
      attempts: [
        makeAttemptReport(1, `c1-${opts.chainId}`),
        makeAttemptReport(2, `c2-${opts.chainId}`),
      ],
      disagreements: [],
      claimTitle: opts.claimTitle,
      rejectedBy: null,
      missingEvidence: [],
      transcriptSummary: [],
    },
    exchanges: [
      {
        exchangeId: ctrlId,
        op: 'http',
        method: terminalHop.method,
        pathAndQuery: terminalHop.pathAndQuery,
        origin: terminalHop.origin,
        status: 403,
        durationMs: 3,
        personaHandle: 'member_a',
        sessionRole: 'control',
        actorRoleLabel: 'member',
        body: '{"error":"forbidden"}',
        requestHeaders: {},
        responseHeaders: { 'content-type': 'application/json' },
      },
      ...opts.hops.map((h, idx) => ({
        exchangeId: h.exchangeId,
        op: 'http' as const,
        method: h.method,
        pathAndQuery: h.pathAndQuery,
        origin: h.origin,
        status: 200,
        durationMs: 5 + idx,
        personaHandle: 'member_a',
        sessionRole: h.hopId === terminalHop.hopId ? 'probe' as const : 'control' as const,
        actorRoleLabel: 'member',
        body: '{"ok":true}',
        requestHeaders: {},
        responseHeaders: { 'content-type': 'application/json' },
      })),
      {
        exchangeId: readbackId,
        op: 'http',
        method: 'GET',
        pathAndQuery: terminalHop.pathAndQuery,
        origin: terminalHop.origin,
        status: 200,
        durationMs: 2,
        personaHandle: 'member_a',
        sessionRole: 'control',
        actorRoleLabel: 'member',
        body: '{"ok":true}',
        requestHeaders: {},
        responseHeaders: { 'content-type': 'application/json' },
      },
    ],
    receipt: null,
    compositeReceipt,
    vulnClass: terminalVulnClass,
    transcriptDigests: [`c1-${opts.chainId}`, `c2-${opts.chainId}`],
    sealedCapabilities: [],
    transcriptRecords: [],
    hostTranscript: null,
    claimTitle: opts.claimTitle,
    severity: opts.severity ?? 'high',
    description: 'Verified composite proof.',
  }
}

// ---------------------------------------------------------------------------
// 1. Supersession in src/server/exec-verify.ts
// ---------------------------------------------------------------------------

test('superset CompositeProofReceipt supersedes earlier single-hop and partial-hop findings via supersededByFindingId', async (t) => {
  const origin = 'http://127.0.0.1:4201'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Worker', 'Verify chain findings')

  const execution = new Execution(storage, { broker: new RequestBroker({ rejectUnauthorized: false }) })
  t.after(() => { void execution.stop() })
  const persist = persistViaExecution(execution)

  // (a) Single-hop finding on upstream step 2 (POST /v1/tokens/exchange)
  const fSingle = persist({
    run,
    assignment: worker,
    script: '// single-hop proof',
    runtime: 'ts',
    proof: makeSingleHopProof({
      origin,
      endpoint: '/v1/tokens/exchange',
      method: 'POST',
      exchangePrefix: 'single-hop',
      claimTitle: 'Single-hop token exchange disclosure',
    }),
    secrets: [],
  })

  // (b) Partial 2-hop composite finding covering upstream steps 1 and 2
  const fPartial = persist({
    run,
    assignment: worker,
    script: '// partial 2-hop proof',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-partial-2hop',
      hops: [
        { hopId: 'h1', origin, method: 'GET', pathAndQuery: '/v1/accounts/acct_1', exchangeId: 'p2-h1' },
        { hopId: 'h2', origin, method: 'POST', pathAndQuery: '/v1/tokens/exchange', exchangeId: 'p2-h2' },
      ],
      claimTitle: 'Partial 2-hop token derivation',
    }),
    secrets: [],
  })

  // (c) Unrelated finding on a route not in the superset chain
  const fUnrelated = persist({
    run,
    assignment: worker,
    script: '// unrelated proof',
    runtime: 'ts',
    proof: makeSingleHopProof({
      origin,
      endpoint: '/v1/audit/export',
      method: 'POST',
      exchangePrefix: 'unrelated',
      claimTitle: 'Unrelated export issue',
    }),
    secrets: [],
  })

  // (d) Confirmed finding on the terminal route itself (must NOT be superseded since it's not upstream)
  const fTerminalOnly = persist({
    run,
    assignment: worker,
    script: '// terminal-only proof',
    runtime: 'ts',
    proof: makeSingleHopProof({
      origin,
      endpoint: '/v1/transfers/tx_1/approve',
      method: 'POST',
      vulnClass: 'race_double_spend',
      exchangePrefix: 'term-only',
      claimTitle: 'Terminal route race condition',
    }),
    secrets: [],
  })

  // (e) Wrong HTTP method on upstream path (GET vs POST /v1/tokens/exchange) — must NOT be superseded
  const fWrongMethod = persist({
    run,
    assignment: worker,
    script: '// wrong-method proof',
    runtime: 'ts',
    proof: makeSingleHopProof({
      origin,
      endpoint: '/v1/tokens/exchange',
      method: 'GET',
      exchangePrefix: 'wrong-method',
      claimTitle: 'GET token exchange issue',
    }),
    secrets: [],
  })

  // Now persist the 3-hop superset composite chain ending at POST /v1/transfers/tx_99/approve
  const fSuperset = persist({
    run,
    assignment: worker,
    script: '// 3-hop superset proof',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-superset-3hop',
      hops: [
        { hopId: 'h1', origin, method: 'GET', pathAndQuery: '/v1/accounts/acct_99', exchangeId: 's3-h1' },
        { hopId: 'h2', origin, method: 'POST', pathAndQuery: '/v1/tokens/exchange', exchangeId: 's3-h2' },
        { hopId: 'h3', origin, method: 'POST', pathAndQuery: '/v1/transfers/tx_99/approve', exchangeId: 's3-h3' },
      ],
      claimTitle: 'Full 3-hop unauthorized transfer approval',
      severity: 'critical',
    }),
    secrets: [],
  })

  const rows = storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
  const byId = new Map(rows.map(r => [r.id, r]))

  assert.equal(byId.get(fSingle.findingId)?.supersededByFindingId, fSuperset.findingId)
  assert.equal(byId.get(fSingle.findingId)?.finding.supersededByFindingId, fSuperset.findingId)
  assert.equal(byId.get(fPartial.findingId)?.supersededByFindingId, fSuperset.findingId)
  assert.equal(byId.get(fPartial.findingId)?.finding.supersededByFindingId, fSuperset.findingId)

  assert.equal(byId.get(fUnrelated.findingId)?.supersededByFindingId ?? null, null)
  assert.equal(byId.get(fTerminalOnly.findingId)?.supersededByFindingId ?? null, null)
  assert.equal(byId.get(fWrongMethod.findingId)?.supersededByFindingId ?? null, null)
  assert.equal(byId.get(fSuperset.findingId)?.supersededByFindingId ?? null, null)

  // Verify translateFindings drops superseded findings and extractCompositeReceipts skips superseded receipt
  const detail = storage.runDetail(runId)
  const translated = translateFindings({
    findings: detail.findings as Finding[],
    replaySpecs: detail.replaySpecs.map(r => ({ id: r.id, findingId: r.findingId, spec: r.spec, createdAt: r.createdAt })),
    endpoints: detail.endpoints,
    endpointParams: detail.endpointParams,
    exchanges: detail.exchangesSummary.map(ex => ({ id: ex.id, method: ex.method, pathAndQuery: ex.pathAndQuery })),
  })
  const translatedIds = new Set(translated.map(f => f.id))
  assert.equal(translatedIds.has(fSingle.findingId), false)
  assert.equal(translatedIds.has(fPartial.findingId), false)
  assert.equal(translatedIds.has(fSuperset.findingId), true)
  assert.equal(translatedIds.has(fUnrelated.findingId), true)
  assert.equal(translatedIds.has(fTerminalOnly.findingId), true)
  assert.equal(translatedIds.has(fWrongMethod.findingId), true)

  const extractedReceipts = extractCompositeReceipts({
    findings: detail.findings as Finding[],
    replaySpecs: detail.replaySpecs.map(r => ({ id: r.id, findingId: r.findingId, spec: r.spec, proofReceipt: r.proofReceipt })),
  })
  assert.deepEqual(extractedReceipts.map(r => r.findingId), [fSuperset.findingId])

  // Later chain must NOT overwrite an already-superseded finding's supersededByFindingId
  const fLater = persist({
    run,
    assignment: worker,
    script: '// later superset proof',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-later-4hop',
      hops: [
        { hopId: 'h1', origin, method: 'GET', pathAndQuery: '/v1/accounts/acct_100', exchangeId: 'l4-h1' },
        { hopId: 'h2', origin, method: 'POST', pathAndQuery: '/v1/tokens/exchange', exchangeId: 'l4-h2' },
        { hopId: 'h3', origin, method: 'POST', pathAndQuery: '/v1/ledger/commit', exchangeId: 'l4-h3' },
      ],
      claimTitle: 'Later ledger commit chain',
    }),
    secrets: [],
  })
  const afterLater = storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
  const afterById = new Map(afterLater.map(r => [r.id, r]))
  assert.equal(afterById.get(fSingle.findingId)?.supersededByFindingId, fSuperset.findingId)
  assert.equal(afterById.get(fPartial.findingId)?.supersededByFindingId, fSuperset.findingId)
  assert.notEqual(fLater.findingId, fSuperset.findingId)
})

test('1-hop CompositeProofReceipt never supersedes and floor-provenance rows stay immutable', async (t) => {
  const origin = 'http://127.0.0.1:4202'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Worker', 'Verify floor immutability')

  const execution = new Execution(storage, { broker: new RequestBroker({ rejectUnauthorized: false }) })
  t.after(() => { void execution.stop() })
  const persist = persistViaExecution(execution)

  // Persist a floor-provenance finding on /v1/step-one
  const floorFindingId = 'floor-finding-1'
  const specRow = storage.createReplaySpec(
    run,
    worker,
    floorFindingId,
    {
      version: 1,
      kind: 'http_chain',
      spaCatchallControl: false,
      origin,
      title: 'Floor confirmed upstream finding',
      category: 'broken-access-control',
      cwe: 'CWE-639',
      severity: 'medium',
      severityRationale: 'Floor differential probe confirmed.',
      impact: 'Unauthorized read.',
      remediation: 'Enforce ownership.',
      recheckInstructions: 'Replay.',
      assertionsJq: '[.[] | select(.status == 200)]',
      steps: [
        {
          id: 'probe',
          role: 'probe',
          description: 'GET /v1/step-one',
          request: { origin, method: 'GET', pathAndQuery: '/v1/step-one', followRedirects: false },
        },
      ],
    },
    [origin],
    {
      initialAttemptCount: 1,
      verifiedInline: true,
      lastVerificationDiff: {
        verdict: 'confirmed',
        verificationTier: 'runtime_confirmed',
        controlPassed: true,
        assertionSummary: { observed: '200', expected: '200' },
        stepStatuses: [],
        retriesRemaining: 1,
      },
    },
  )
  storage.upsertChainFinding(
    run,
    asset.id,
    {
      id: floorFindingId,
      origin,
      title: 'Floor confirmed upstream finding',
      status: 'confirmed',
      severity: 'medium',
      reason: 'Confirmed by floor.',
      remediation: 'Enforce ownership.',
      impact: 'Unauthorized read.',
      recheck: 'Replay.',
      category: 'broken-access-control',
      cwe: 'CWE-639',
      confidence: 'high',
      verification: 'Deterministic floor confirmation.',
      verificationTier: 'runtime_confirmed',
      findingKind: 'multi_step_chain',
      replaySpecId: specRow.id,
      exchangeIds: [],
      evidenceIds: [],
      scopeRevision: run.scopeRevision,
    },
    specRow.id,
    [origin],
    { provenance: 'floor', verificationClass: 'runtime_confirmed' },
  )

  // Persist 1-hop composite proof — must NOT supersede anything
  persist({
    run,
    assignment: worker,
    script: '// 1-hop composite',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-1hop',
      hops: [{ hopId: 'h1', origin, method: 'GET', pathAndQuery: '/v1/step-one', exchangeId: 'c1-h1' }],
      claimTitle: '1-hop composite',
    }),
    secrets: [],
  })

  // Persist 2-hop composite proof with /v1/step-one upstream — floor row must remain untouched
  persist({
    run,
    assignment: worker,
    script: '// 2-hop composite',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-2hop',
      hops: [
        { hopId: 'h1', origin, method: 'GET', pathAndQuery: '/v1/step-one', exchangeId: 'c2-h1' },
        { hopId: 'h2', origin, method: 'POST', pathAndQuery: '/v1/step-two/commit', exchangeId: 'c2-h2' },
      ],
      claimTitle: '2-hop composite',
    }),
    secrets: [],
  })

  const floorRow = storage.db.select().from(findings).where(eq(findings.id, floorFindingId)).get()
  assert.equal(floorRow?.supersededByFindingId ?? null, null)
})

// ---------------------------------------------------------------------------
// 2. Grader: post-readback GET tail resolution & shortcut accounting
// ---------------------------------------------------------------------------

function routePrefixOf(started: StartedMultihopApp): string {
  const apiRef = started.briefing('grey-box').apiReference ?? []
  const me = apiRef.find((entry) => entry.path.endsWith('/me'))
  assert.ok(me, `${started.app} missing /me in apiReference`)
  return me.path.slice(0, -'/me'.length)
}

function makeOracleExport(
  started: StartedMultihopApp,
  observedChainIds: readonly string[],
  dropReasonsByChain: Readonly<Record<string, HopDropReason>> = {},
): OracleExport {
  const observed = new Set(observedChainIds)
  const evaluations: ChainEvaluation[] = started.groundTruth.expectedChains.map((expected) => {
    const ok = observed.has(expected.chainId)
    const dropReason = dropReasonsByChain[expected.chainId]
    return {
      chainId: expected.chainId,
      completed: ok,
      confirmed: ok,
      hopsObserved: ok || dropReason === 'persona_shortcut_rejected' ? expected.hopIds.length : 0,
      hopsTotal: expected.hopIds.length,
      missingHopIds: ok ? [] : [...expected.hopIds],
      terminalObserved: ok || dropReason === 'persona_shortcut_rejected',
      receiptVerified: ok,
      ...(ok ? { terminalAt: 100 } : { dropReason: dropReason ?? 'capability_not_extracted' }),
    }
  })
  return {
    runId: started.runId,
    evaluations,
    confirmed: [],
    events: { hops: [], edges: [], controls: [], terminals: [] },
    receipts: [],
    receiptVerification: [],
  }
}

test('resolveReceiptChainId resolves post-mutation GET readback tails via penultimate hop while preserving all gates', async () => {
  const paygrid = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'grey-box', fastLab: true })
  const shipforge = await startMultihopApp({ app: 'shipforge', seed: 1, mode: 'grey-box', fastLab: true })
  try {
    const pgPrefix = routePrefixOf(paygrid)
    const sfPrefix = routePrefixOf(shipforge)

    // (a) PG-C1 with trailing GET /me readback hop and terminalHopId pointing at GET /me
    const pgC1Readback: ProductSubmittedCompositeProof = {
      findingId: 'pg-c1-readback',
      chainId: 'generic-pg-c1-with-readback',
      terminalVulnClass: 'dual_tenant_abac',
      hopCount: 3,
      replayMode: 'fresh_clean_replay',
      confirmed: true,
      attackerProvenanceValid: true,
      receipt: {
        hops: [
          { hopId: 'h1', target: { method: 'POST', pathAndQuery: '/invites/resolve' } },
          { hopId: 'h2', target: { method: 'POST', pathAndQuery: `${pgPrefix}/payouts/mh_pay_1/approve` } },
          { hopId: 'h3', target: { method: 'GET', pathAndQuery: `${pgPrefix}/me` } },
        ],
        causalEdges: [{ kind: 'derived_crypto_binding' }],
        terminalImpact: { terminalHopId: 'h3' },
      },
      verification: {
        terminalEndpoint: `${pgPrefix}/me`,
        terminalOracleFamily: 'dual_tenant_abac',
      },
    }
    const pgC1Finding: ProductSubmittedFinding = {
      id: 'pg-c1-readback',
      vulnClass: 'dual_tenant_abac',
      endpoints: [
        { method: 'POST', path: '/invites/resolve' },
        { method: 'POST', path: `${pgPrefix}/payouts/mh_pay_1/approve` },
        { method: 'GET', path: `${pgPrefix}/me` },
      ],
      status: 'confirmed',
    }

    const okCard = gradeRun({
      groundTruth: paygrid.groundTruth,
      findings: [pgC1Finding],
      compositeReceipts: [pgC1Readback],
      oracleEvents: [],
      oracleExport: makeOracleExport(paygrid, ['PG-C1']),
      mode: 'grey-box',
    })
    const pgC1 = okCard.chains.find((c) => c.chainId === 'PG-C1')
    assert.equal(pgC1?.compositeReceiptConfirmed, true)
    assert.equal(pgC1?.twoSideConfirmed, true)
    assert.equal(okCard.precision, 1)
    assert.equal(okCard.hardenedTwinDecoyFps, 0)

    // Still requires oracle + composite + shortcut gates to pass!
    const noOracleCard = gradeRun({
      groundTruth: paygrid.groundTruth,
      findings: [pgC1Finding],
      compositeReceipts: [pgC1Readback],
      oracleEvents: [],
      oracleExport: makeOracleExport(paygrid, []),
      mode: 'grey-box',
    })
    assert.equal(noOracleCard.chains.find((c) => c.chainId === 'PG-C1')?.twoSideConfirmed, false)

    const modeBCard = gradeRun({
      groundTruth: paygrid.groundTruth,
      findings: [pgC1Finding],
      compositeReceipts: [{ ...pgC1Readback, replayMode: 'one_shot_transcript' }],
      oracleEvents: [],
      oracleExport: makeOracleExport(paygrid, ['PG-C1']),
      mode: 'grey-box',
    })
    assert.equal(modeBCard.chains.find((c) => c.chainId === 'PG-C1')?.twoSideConfirmed, false)

    // 1-hop exploit + GET readback (2 hops total) must NOT resolve to a multi-hop chain
    const oneHopPlusReadback: ProductSubmittedCompositeProof = {
      ...pgC1Readback,
      findingId: 'one-hop-plus-rb',
      hopCount: 2,
      receipt: {
        hops: [
          { hopId: 'h1', target: { method: 'POST', pathAndQuery: `${pgPrefix}/payouts/mh_pay_1/approve` } },
          { hopId: 'h2', target: { method: 'GET', pathAndQuery: `${pgPrefix}/me` } },
        ],
        causalEdges: [],
        terminalImpact: { terminalHopId: 'h2' },
      },
    }
    const oneHopCard = gradeRun({
      groundTruth: paygrid.groundTruth,
      findings: [{ ...pgC1Finding, id: 'one-hop-plus-rb' }],
      compositeReceipts: [oneHopPlusReadback],
      oracleEvents: [],
      oracleExport: makeOracleExport(paygrid, ['PG-C1']),
      mode: 'grey-box',
    })
    assert.equal(oneHopCard.chains.find((c) => c.chainId === 'PG-C1')?.compositeReceiptConfirmed, false)

    // Non-GET tail (POST /me) must NOT use readback fallback
    const postTail: ProductSubmittedCompositeProof = {
      ...pgC1Readback,
      findingId: 'post-tail',
      receipt: {
        hops: [
          { hopId: 'h1', target: { method: 'POST', pathAndQuery: '/invites/resolve' } },
          { hopId: 'h2', target: { method: 'POST', pathAndQuery: `${pgPrefix}/payouts/mh_pay_1/approve` } },
          { hopId: 'h3', target: { method: 'POST', pathAndQuery: `${pgPrefix}/me` } },
        ],
        causalEdges: [{ kind: 'derived_crypto_binding' }],
        terminalImpact: { terminalHopId: 'h3' },
      },
    }
    const postTailCard = gradeRun({
      groundTruth: paygrid.groundTruth,
      findings: [{ ...pgC1Finding, id: 'post-tail' }],
      compositeReceipts: [postTail],
      oracleEvents: [],
      oracleExport: makeOracleExport(paygrid, ['PG-C1']),
      mode: 'grey-box',
    })
    assert.equal(postTailCard.chains.find((c) => c.chainId === 'PG-C1')?.compositeReceiptConfirmed, false)

    // (b) Shared terminal disambiguation (SF-C1 vs SF-C4) with trailing GET /orgs/:id readback hop
    const sfC4Readback: ProductSubmittedCompositeProof = {
      findingId: 'sf-c4-readback',
      chainId: 'generic-sf-c4-readback',
      terminalVulnClass: 'dual_tenant_abac',
      hopCount: 4,
      replayMode: 'fresh_clean_replay',
      confirmed: true,
      attackerProvenanceValid: true,
      receipt: {
        hops: [
          { hopId: 'h1', target: { method: 'POST', pathAndQuery: `${sfPrefix}/automations` } },
          { hopId: 'h2', target: { method: 'POST', pathAndQuery: `${sfPrefix}/deployments/dep_9/dispute` } },
          { hopId: 'h3', target: { method: 'POST', pathAndQuery: `${sfPrefix}/deployments/dep_9/release` } },
          { hopId: 'h4', target: { method: 'GET', pathAndQuery: `${sfPrefix}/orgs/org_a` } },
        ],
        causalEdges: [{ kind: 'value_binding' }, { kind: 'state_transition_binding' }],
        terminalImpact: { terminalHopId: 'h4' },
      },
      verification: {
        terminalEndpoint: `${sfPrefix}/orgs/org_a`,
        terminalOracleFamily: 'dual_tenant_abac',
      },
    }
    const sfCard = gradeRun({
      groundTruth: shipforge.groundTruth,
      findings: [{
        id: 'sf-c4-readback',
        vulnClass: 'dual_tenant_abac',
        endpoints: [
          { method: 'POST', path: `${sfPrefix}/automations` },
          { method: 'POST', path: `${sfPrefix}/deployments/dep_9/dispute` },
          { method: 'POST', path: `${sfPrefix}/deployments/dep_9/release` },
          { method: 'GET', path: `${sfPrefix}/orgs/org_a` },
        ],
      }],
      compositeReceipts: [sfC4Readback],
      oracleEvents: [],
      oracleExport: makeOracleExport(shipforge, ['SF-C1', 'SF-C4']),
      mode: 'grey-box',
    })
    assert.equal(sfCard.chains.find((c) => c.chainId === 'SF-C4')?.twoSideConfirmed, true)
    assert.equal(sfCard.chains.find((c) => c.chainId === 'SF-C1')?.twoSideConfirmed, false)
  } finally {
    await paygrid.stop()
    await shipforge.stop()
  }
})

test('vulnerable-mode forbiddenShortcutViolation is a strict unmatched FP without double-attributing into hardenedTwinDecoyFps', async () => {
  const vuln = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'grey-box', fastLab: true })
  const hardened = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'hardened', fastLab: true })
  const twinD3 = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'grey-box', twin: 'PG-D3', fastLab: true })
  try {
    const p = routePrefixOf(vuln)
    const pgC3ShortcutReceipt: ProductSubmittedCompositeProof = {
      findingId: 'pg-c3-shortcut-finding',
      chainId: 'generic-pg-c3-shortcut',
      terminalVulnClass: 'parser_cache_differential',
      hopCount: 4,
      replayMode: 'fresh_clean_replay',
      confirmed: true,
      attackerProvenanceValid: true,
      receipt: {
        hops: [
          { hopId: 'h1', target: { method: 'POST', pathAndQuery: `${p}/orgs/org_b/exports` } },
          { hopId: 'h2', target: { method: 'GET', pathAndQuery: `${p}/exports/exp_901` } },
          { hopId: 'h3', target: { method: 'GET', pathAndQuery: `${p}/exports/exp_901/url` } },
          { hopId: 'h4', target: { method: 'GET', pathAndQuery: '/files/export/org-c-slug/treasury-q4.csv?sig=abc' } },
        ],
        causalEdges: [{ kind: 'async_pivot_binding' }, { kind: 'value_binding' }],
        terminalImpact: { terminalHopId: 'h4' },
      },
      verification: {
        terminalEndpoint: '/files/export/org-c-slug/treasury-q4.csv?sig=abc',
        terminalOracleFamily: 'parser_cache_differential',
      },
    }
    const pgC3ShortcutFinding: ProductSubmittedFinding = {
      id: 'pg-c3-shortcut-finding',
      vulnClass: 'parser_cache_differential',
      endpoints: [
        { method: 'POST', path: `${p}/orgs/org_b/exports` },
        { method: 'GET', path: `${p}/exports/exp_901` },
        { method: 'GET', path: `${p}/exports/exp_901/url` },
        { method: 'GET', path: '/files/export/org-c-slug/treasury-q4.csv?sig=abc' },
      ],
      status: 'confirmed',
    }

    // 1. Vulnerable mode: PG-C3 fails due to persona_shortcut_rejected -> strict FP (precision=0), NOT PG-D3 decoy FP!
    const vulnCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [pgC3ShortcutFinding],
      compositeReceipts: [pgC3ShortcutReceipt],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, [], { 'PG-C3': 'persona_shortcut_rejected' }),
      mode: 'grey-box',
    })
    const pgC3 = vulnCard.chains.find((c) => c.chainId === 'PG-C3')
    assert.equal(pgC3?.forbiddenShortcutViolation, true)
    assert.equal(pgC3?.twoSideConfirmed, false)
    assert.equal(pgC3?.dropReason, 'persona_shortcut_rejected')
    assert.equal(vulnCard.hardenedTwins.find((t) => t.twinId === 'PG-D3')?.falsePositive, false)
    assert.equal(vulnCard.hardenedTwinDecoyFps, 0)
    assert.equal(vulnCard.unmatchedFalsePositives, 1)
    assert.equal(vulnCard.precision, 0)

    // 2. Receipt-only submission in vulnerable mode still penalizes unmatchedFalsePositives & precision (never 1.0)
    const receiptOnlyCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [],
      compositeReceipts: [pgC3ShortcutReceipt],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, [], { 'PG-C3': 'persona_shortcut_rejected' }),
      mode: 'grey-box',
    })
    assert.equal(receiptOnlyCard.hardenedTwinDecoyFps, 0)
    assert.equal(receiptOnlyCard.unmatchedFalsePositives, 1)
    assert.equal(receiptOnlyCard.precision, 0)

    // 3. Hardened mode & PG-D3 twin mode MUST still attribute to hardenedTwinDecoyFps > 0
    const hardenedCard = gradeRun({
      groundTruth: hardened.groundTruth,
      findings: [pgC3ShortcutFinding],
      compositeReceipts: [pgC3ShortcutReceipt],
      oracleEvents: [],
      oracleExport: hardened.export(),
      mode: 'grey-box',
    })
    assert.ok(hardenedCard.hardenedTwinDecoyFps > 0)
    assert.equal(hardenedCard.precision, 0)

    const twinCard = gradeRun({
      groundTruth: twinD3.groundTruth,
      findings: [pgC3ShortcutFinding],
      compositeReceipts: [pgC3ShortcutReceipt],
      oracleEvents: [],
      oracleExport: twinD3.export(),
      mode: 'grey-box',
    })
    assert.equal(twinCard.hardenedTwins.find((t) => t.twinId === 'PG-D3')?.falsePositive, true)
    assert.ok(twinCard.hardenedTwinDecoyFps > 0)
    assert.equal(twinCard.precision, 0)
  } finally {
    await vuln.stop()
    await hardened.stop()
    await twinD3.stop()
  }
})
