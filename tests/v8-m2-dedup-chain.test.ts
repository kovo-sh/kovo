/**
 * Regression suite for M2 multi-step chain DAG deduplication (`src/server/exec-verify.ts`,
 * `src/server/store-findings.ts`) and vulnerable-mode duplicate-attribution grading
 * (`benchmarks/multihop-saas/run.ts`):
 *  1. Same-terminal different-`terminalOracleFamily` / CWE `multi_step_chain` (with shared upstream
 *     hop) collapses to 1 finding preferring the deeper/richer chain, plus action-vs-readback and
 *     same-terminal+same-chainId collapse without downgrading.
 *  2. Deeper chain supersedes shallower compatible/precondition intermediate-hop chain cleanly
 *     (and late subset collapses into deeper chain), while a distinct-class shallow chain whose
 *     terminal is merely an intermediate hop of a deeper chain stays active (R3-05 #4).
 *  3. Negative separation guards: disjoint chains, shared-terminal disjoint-upstream chains,
 *     divergent-terminal chains, distinct loopback ports (R3-05 #5), colliding agent-chosen
 *     chainIds on distinct terminals (R3-05 #6), and same-terminal different-class chains with
 *     empty non-generic upstream + narrowed `/auth/*` generic filter (R3-05 #7).
 *  4. `gradeRun` (`gradeProductRun`): vulnerable-mode confirmed-duplicate exemption (strictly
 *     requiring confirmed Mode-A receipt, ignoring self-declared `chainId`), vulnerable-only
 *     `supersededByFindingId` filtering (explicit `status === 'confirmed'`, confirmed non-decoy
 *     winner, loser-winner relation), and 100% strictness in hardened/twin mode (R3-05 #1-#3).
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
import type { ChainEvaluation, OracleExport } from '../benchmarks/multihop-saas/lib/types.ts'
import { extractCompositeReceipts } from '../scripts/benchmark-multihop.ts'
import { translateFindings } from '../scripts/benchmark-realistic.ts'
import type { Finding } from '../src/domain.ts'
import { filterActiveFindings } from '../src/report-summary.ts'
import type { AgentScriptProofResult, V8CompositeProofBundle } from '../src/server/agent-script-proof.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import { findings } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import {
  compositeChainOriginsEquivalent,
  isGenericSharedAuthOrUtilityEndpoint,
} from '../src/server/store-findings.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

function makeStore(t: test.TestContext): { storage: Store; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v8-m2-dedup-chain-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
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

function makeCompositeProof(opts: {
  chainId: string
  terminalVulnClass: string
  terminalOracleFamily?: string
  hops: Array<{
    hopId: string
    origin: string
    method: string
    pathAndQuery: string
    exchangeId: string
    preconditionVulnClass?: string
  }>
  terminalHopId?: string
  claimTitle: string
  severity?: 'low' | 'medium' | 'high' | 'critical'
  verifiedEdgeCount?: number
}): AgentScriptProofResult {
  const terminalOracleFamily = opts.terminalOracleFamily ?? opts.terminalVulnClass
  const terminalHop = opts.hops.find(h => h.hopId === opts.terminalHopId) ?? opts.hops[opts.hops.length - 1]!
  const ctrlId = `${opts.chainId}-ctrl`
  const readbackId = `${opts.chainId}-rb`
  const edgeCount = opts.verifiedEdgeCount ?? Math.max(0, opts.hops.length - 1)
  const causalEdges = Array.from({ length: edgeCount }, (_, idx) => ({
    fromHopId: opts.hops[Math.min(idx, opts.hops.length - 1)]!.hopId,
    toHopId: opts.hops[Math.min(idx + 1, opts.hops.length - 1)]!.hopId,
    kind: 'value_binding' as const,
    capabilityHandle: `cap_${idx}`,
  }))
  const verifiedEdges = causalEdges.map((e, edgeIndex) => ({
    edgeIndex,
    fromHopId: e.fromHopId,
    toHopId: e.toHopId,
    kind: e.kind,
    verified: true,
    reason: 'verified',
  }))

  const compositeReceipt: V8CompositeProofBundle = {
    receipt: {
      chainId: opts.chainId,
      terminalVulnClass: opts.terminalVulnClass,
      replayMode: 'fresh_clean_replay',
      hops: opts.hops.map(h => ({
        hopId: h.hopId,
        surface: 'http',
        target: { origin: h.origin, method: h.method, pathAndQuery: h.pathAndQuery },
        exchangeIds: [h.exchangeId],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: `Hop ${h.hopId} delta`,
        producedCapabilities: [],
        consumedCapabilities: [],
        ...(h.preconditionVulnClass ? {
          proofReceipt: {
            vulnClass: h.preconditionVulnClass,
            target: { origin: h.origin, method: h.method, pathAndQuery: h.pathAndQuery },
            exchangeIds: [h.exchangeId],
            oobEventIds: [],
            browserTraceIds: [],
            claimedDelta: `Precondition ${h.preconditionVulnClass}`,
          },
        } : {}),
      })),
      causalEdges,
      terminalImpact: {
        terminalHopId: terminalHop.hopId,
        claimedImpact: 'Confirmed multi-hop terminal impact.',
        summary: 'Confirmed multi-hop terminal impact.',
        terminalExchangeId: terminalHop.exchangeId,
        oracleFamily: terminalOracleFamily as V8CompositeProofBundle['receipt']['terminalImpact']['oracleFamily'],
        preChainControlExchangeIds: [ctrlId],
        postChainReadbackExchangeIds: [readbackId],
      },
    },
    verification: {
      confirmed: true,
      chainId: opts.chainId,
      terminalVulnClass: opts.terminalVulnClass,
      replayMode: 'fresh_clean_replay',
      modeBVerified: false,
      hopCount: opts.hops.length,
      verifiedEdges,
      reason: 'Composite chain verified.',
      terminalOracleFamily,
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
    vulnClass: opts.terminalVulnClass,
    transcriptDigests: [`c1-${opts.chainId}`, `c2-${opts.chainId}`],
    sealedCapabilities: [],
    transcriptRecords: [],
    hostTranscript: null,
    claimTitle: opts.claimTitle,
    severity: opts.severity ?? 'high',
    description: 'Verified composite proof.',
  }
}

function routePrefixOf(started: StartedMultihopApp): string {
  const apiRef = started.briefing('grey-box').apiReference ?? []
  const me = apiRef.find((entry) => entry.path.endsWith('/me'))
  assert.ok(me, `${started.app} missing /me in apiReference`)
  return me.path.slice(0, -'/me'.length)
}

function makeOracleExport(
  started: StartedMultihopApp,
  observedChainIds: readonly string[],
): OracleExport {
  const observed = new Set(observedChainIds)
  const evaluations: ChainEvaluation[] = started.groundTruth.expectedChains.map((expected) => {
    const ok = observed.has(expected.chainId)
    return {
      chainId: expected.chainId,
      completed: ok,
      confirmed: ok,
      hopsObserved: ok ? expected.hopIds.length : 0,
      hopsTotal: expected.hopIds.length,
      missingHopIds: ok ? [] : [...expected.hopIds],
      terminalObserved: ok,
      receiptVerified: ok,
      ...(ok ? { terminalAt: 100 } : { dropReason: 'capability_not_extracted' }),
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

// ---------------------------------------------------------------------------
// 1. Same-terminal different-oracleFamily, action-vs-readback, deeper upgrade
// ---------------------------------------------------------------------------

test('1. same-terminal different-oracleFamily multi_step_chain (shared upstream) collapses to 1 finding preferring deeper chain, plus action-vs-readback collapse', async (t) => {
  const origin = 'http://127.0.0.1:4711'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Worker', 'Dedup chain proofs')

  const execution = new Execution(storage, { broker: new RequestBroker({ rejectUnauthorized: false }) })
  t.after(() => { void execution.stop() })
  const persist = persistViaExecution(execution)

  // (a) Shallower 2-hop proof labeled `dual_tenant_abac` (CWE-639) arrives first
  const shallow = persist({
    run,
    assignment: worker,
    script: '// shallow 2-hop proof',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-settle-abac-2hop',
      terminalVulnClass: 'dual_tenant_abac',
      hops: [
        { hopId: 'h1', origin, method: 'POST', pathAndQuery: '/v1/documents/doc_1/render', exchangeId: 'sh-h1' },
        { hopId: 'h2', origin, method: 'POST', pathAndQuery: '/v1/callbacks/settle', exchangeId: 'sh-h2' },
      ],
      claimTitle: 'Cross-tenant callback settlement (2-hop)',
    }),
    secrets: [],
  })

  // (b) Deeper 4-hop proof on the SAME terminal sharing upstream /v1/documents/:id/render labeled `economic_conservation` (CWE-840)
  const deeper = persist({
    run,
    assignment: worker,
    script: '// deeper 4-hop proof',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-settle-econ-4hop',
      terminalVulnClass: 'economic_conservation',
      hops: [
        { hopId: 'h1', origin, method: 'PATCH', pathAndQuery: '/v1/templates/tpl_1', exchangeId: 'dp-h1' },
        { hopId: 'h2', origin, method: 'POST', pathAndQuery: '/v1/documents/doc_2/render', exchangeId: 'dp-h2' },
        { hopId: 'h3', origin, method: 'GET', pathAndQuery: '/v1/jobs/job_2/trace', exchangeId: 'dp-h3' },
        { hopId: 'h4', origin, method: 'POST', pathAndQuery: '/v1/callbacks/settle', exchangeId: 'dp-h4' },
      ],
      claimTitle: 'Economic conservation bypass via callback settlement (4-hop)',
    }),
    secrets: [],
  })

  assert.equal(deeper.findingId, shallow.findingId, 'same-terminal different-oracleFamily multi-hop chain with shared upstream must collapse to 1 finding')
  assert.notEqual(deeper.replaySpecId, shallow.replaySpecId, 'deeper 4-hop proof must upgrade canonical replaySpecId over shallower 2-hop proof')

  // (c) Action+readback variant (5 hops with trailing GET /v1/orgs/org_9 readback) collapses into the same finding
  const withReadback = persist({
    run,
    assignment: worker,
    script: '// 5-hop proof with readback tail',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-settle-readback-5hop',
      terminalVulnClass: 'cryptographic_scope_replay',
      hops: [
        { hopId: 'h1', origin, method: 'PATCH', pathAndQuery: '/v1/templates/tpl_9', exchangeId: 'rb-h1' },
        { hopId: 'h2', origin, method: 'POST', pathAndQuery: '/v1/documents/doc_9/render', exchangeId: 'rb-h2' },
        { hopId: 'h3', origin, method: 'GET', pathAndQuery: '/v1/jobs/job_9/trace', exchangeId: 'rb-h3' },
        { hopId: 'h4', origin, method: 'POST', pathAndQuery: '/v1/callbacks/settle', exchangeId: 'rb-h4' },
        { hopId: 'h5', origin, method: 'GET', pathAndQuery: '/v1/orgs/org_9', exchangeId: 'rb-h5' },
      ],
      claimTitle: 'Callback settlement verified via org readback',
    }),
    secrets: [],
  })
  assert.equal(withReadback.findingId, shallow.findingId, 'action-terminal vs action+GET-readback must collapse to 1 finding')

  // (d) Shallower proof arriving AFTER deeper proof on same terminal + same chainId must collapse without downgrading
  const sameTerminalShallow = persist({
    run,
    assignment: worker,
    script: '// repeat same terminal + chainId shallower',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-settle-readback-5hop',
      terminalVulnClass: 'dual_tenant_abac',
      hops: [
        { hopId: 'h1', origin, method: 'POST', pathAndQuery: '/v1/documents/doc_10/render', exchangeId: 'cid-h1' },
        { hopId: 'h2', origin, method: 'GET', pathAndQuery: '/v1/orgs/org_10', exchangeId: 'cid-h2' },
      ],
      claimTitle: 'Duplicate terminal + chainId shallower proof',
    }),
    secrets: [],
  })
  assert.equal(sameTerminalShallow.findingId, shallow.findingId, 'same terminal + chainId must collapse to 1 finding')
  assert.equal(sameTerminalShallow.replaySpecId, withReadback.replaySpecId, 'shallower duplicate must not downgrade deeper replaySpecId')

  const rows = storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
  assert.equal(rows.length, 1, 'exactly 1 persisted finding row')
  const storedEv = (rows[0]!.finding as Finding & { evidence?: { compositeReceipt?: { hops?: unknown[] } } }).evidence
  assert.equal(storedEv?.compositeReceipt?.hops?.length, 5, 'persisted compositeReceipt must retain the deepest 5-hop chain')
  assert.equal(rows[0]!.finding.evidenceIds.length, 4, 'all 4 corroborating artifacts preserved')
})

// ---------------------------------------------------------------------------
// 2. Deeper chain supersedes compatible/precondition shallower chain; distinct-class shallow chain stays active (R3-05 #4)
// ---------------------------------------------------------------------------

test('2. deeper chain supersedes compatible/precondition intermediate-hop chain cleanly while distinct-class shallow chain whose terminal is a mid-hop stays active (R3-05 #4)', async (t) => {
  const origin = 'http://127.0.0.1:4712'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Worker', 'Supersede partial chains')

  const execution = new Execution(storage, { broker: new RequestBroker({ rejectUnauthorized: false }) })
  t.after(() => { void execution.stop() })
  const persist = persistViaExecution(execution)

  // (a) Compatible intermediate 2-hop chain (`dual_tenant_abac`, explicitly declared as precondition on hop 2 of deeper chain)
  const partialCompatible = persist({
    run,
    assignment: worker,
    script: '// partial 2-hop intermediate compatible',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-partial-a',
      terminalVulnClass: 'dual_tenant_abac',
      hops: [
        { hopId: 'h1', origin, method: 'PATCH', pathAndQuery: '/v1/templates/tpl_1', exchangeId: 'pa-h1' },
        { hopId: 'h2', origin, method: 'POST', pathAndQuery: '/v1/renders/rnd_1/run', exchangeId: 'pa-h2' },
      ],
      claimTitle: 'Intermediate 2-hop template render abuse',
    }),
    secrets: [],
  })

  // (b) R3-05 #4 negative case: distinct-class 2-hop chain (`temporal_revocation`) whose terminal is a mid-hop
  //     (GET /v1/traces/:id) of the deeper chain, with NO declared precondition on that hop -> MUST STAY ACTIVE!
  const distinctClassMidHop = persist({
    run,
    assignment: worker,
    script: '// distinct-class 2-hop mid-hop chain',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-distinct-class-midhop',
      terminalVulnClass: 'temporal_revocation',
      hops: [
        { hopId: 'h1', origin, method: 'PATCH', pathAndQuery: '/v1/templates/tpl_8', exchangeId: 'dc-h1' },
        { hopId: 'h2', origin, method: 'GET', pathAndQuery: '/v1/traces/tr_8', exchangeId: 'dc-h2' },
      ],
      claimTitle: 'Distinct-class temporal revocation on trace endpoint',
    }),
    secrets: [],
  })

  // (c) Deeper 4-hop full chain (`economic_conservation`) declaring `preconditionVulnClass: 'dual_tenant_abac'` on h2
  const fullSecond = persist({
    run,
    assignment: worker,
    script: '// full 4-hop chain',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-full-a',
      terminalVulnClass: 'economic_conservation',
      hops: [
        { hopId: 'h1', origin, method: 'PATCH', pathAndQuery: '/v1/templates/tpl_2', exchangeId: 'fa-h1' },
        { hopId: 'h2', origin, method: 'POST', pathAndQuery: '/v1/renders/rnd_2/run', exchangeId: 'fa-h2', preconditionVulnClass: 'dual_tenant_abac' },
        { hopId: 'h3', origin, method: 'GET', pathAndQuery: '/v1/traces/tr_2', exchangeId: 'fa-h3' },
        { hopId: 'h4', origin, method: 'POST', pathAndQuery: '/v1/ledger/settle', exchangeId: 'fa-h4' },
      ],
      claimTitle: 'Full 4-hop forged settlement chain',
    }),
    secrets: [],
  })

  assert.notEqual(fullSecond.findingId, partialCompatible.findingId)
  const rowsA = storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
  const byIdA = new Map(rowsA.map(r => [r.id, r]))
  assert.equal(
    byIdA.get(partialCompatible.findingId)?.supersededByFindingId,
    fullSecond.findingId,
    'shallower 2-hop compatible/precondition partial chain must be superseded by deeper 4-hop chain',
  )
  assert.equal(
    byIdA.get(distinctClassMidHop.findingId)?.supersededByFindingId ?? null,
    null,
    'R3-05 #4: distinct-class shallow chain whose terminal is merely a mid-hop of a deeper chain must NOT be superseded',
  )

  // (d) Reverse order: late shallower subset of the deeper chain collapses into the deeper chain directly
  const lateSubset = persist({
    run,
    assignment: worker,
    script: '// late partial 2-hop subset',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-late-subset-a',
      terminalVulnClass: 'economic_conservation',
      hops: [
        { hopId: 'h1', origin, method: 'POST', pathAndQuery: '/v1/renders/rnd_3/run', exchangeId: 'ls-h1' },
        { hopId: 'h2', origin, method: 'GET', pathAndQuery: '/v1/traces/tr_3', exchangeId: 'ls-h2' },
      ],
      claimTitle: 'Late 2-hop intermediate trace subset',
    }),
    secrets: [],
  })
  assert.equal(lateSubset.findingId, fullSecond.findingId, 'late shallower subset arriving after deeper chain must collapse into deeper chain')

  // Verify active finding views expose ONLY fullSecond + distinctClassMidHop (partialCompatible excluded cleanly!)
  const detail = storage.runDetail(runId)
  const activeIds = new Set(filterActiveFindings(detail.findings as Finding[]).filter(f => f.status === 'confirmed').map(f => f.id))
  assert.equal(activeIds.has(fullSecond.findingId), true)
  assert.equal(activeIds.has(distinctClassMidHop.findingId), true)
  assert.equal(activeIds.has(partialCompatible.findingId), false)

  const translatedIds = new Set(translateFindings({
    findings: detail.findings as Finding[],
    replaySpecs: detail.replaySpecs.map(r => ({ id: r.id, findingId: r.findingId, spec: r.spec, createdAt: r.createdAt })),
    endpoints: detail.endpoints,
    endpointParams: detail.endpointParams,
    exchanges: detail.exchangesSummary.map(ex => ({ id: ex.id, method: ex.method, pathAndQuery: ex.pathAndQuery })),
  }).map(f => f.id))
  assert.equal(translatedIds.has(fullSecond.findingId), true)
  assert.equal(translatedIds.has(distinctClassMidHop.findingId), true)
  assert.equal(translatedIds.has(partialCompatible.findingId), false)

  const receiptIds = new Set(extractCompositeReceipts({
    findings: detail.findings as Finding[],
    replaySpecs: detail.replaySpecs.map(r => ({ id: r.id, findingId: r.findingId, spec: r.spec, proofReceipt: r.proofReceipt })),
  }).map(r => r.findingId))
  assert.equal(receiptIds.has(fullSecond.findingId), true)
  assert.equal(receiptIds.has(distinctClassMidHop.findingId), true)
  assert.equal(receiptIds.has(partialCompatible.findingId), false)
})

// ---------------------------------------------------------------------------
// 3. Distinct chains & R3-05 #5/#6/#7 negative separation guards
// ---------------------------------------------------------------------------

test('3. disjoint chains, different loopback ports (#5), colliding chainId on distinct terminals (#6), and same-terminal different-class with empty upstream (#7) stay separate', async (t) => {
  const origin1 = 'http://127.0.0.1:4715'
  const origin2 = 'http://127.0.0.1:4716'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin1, origin2], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset1 = run.candidates.find(c => c.origin === origin1)!
  const asset2 = run.candidates.find(c => c.origin === origin2)!
  const w1 = storage.makeWorker(run, 'investigation', asset1, 'W1', 'Origin 1 chains')
  const w2 = storage.makeWorker(run, 'investigation', asset2, 'W2', 'Origin 2 chains')

  // Pure helper assertions for R3-05 #5 and #7
  assert.equal(compositeChainOriginsEquivalent('http://127.0.0.1:4715', 'http://localhost:4715'), true, 'same-port loopback alias allowed')
  assert.equal(compositeChainOriginsEquivalent('http://127.0.0.1:4715', 'http://127.0.0.1:4716'), false, 'R3-05 #5: distinct loopback ports must NOT match')
  assert.equal(compositeChainOriginsEquivalent('http://127.0.0.1:4715', 'https://127.0.0.1:4715'), false, 'distinct schemes must NOT match')
  assert.equal(isGenericSharedAuthOrUtilityEndpoint('/auth/callback'), true, 'standard /auth/callback remains generic')
  assert.equal(isGenericSharedAuthOrUtilityEndpoint('/auth/invites/redeem'), false, 'R3-05 #7: business route under /auth/* must NOT be generic')
  assert.equal(isGenericSharedAuthOrUtilityEndpoint('/auth/scim/tokens'), false, 'R3-05 #7: /auth/scim/tokens must NOT be generic')

  const execution = new Execution(storage, { broker: new RequestBroker({ rejectUnauthorized: false }) })
  t.after(() => { void execution.stop() })
  const persist = persistViaExecution(execution)

  // Chain 1: disjoint upstream path A -> POST /v1/releases/:id/publish (`cryptographic_scope_replay`)
  const c1 = persist({
    run,
    assignment: w1,
    script: '// chain 1',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'shared-agent-chain-name',
      terminalVulnClass: 'cryptographic_scope_replay',
      hops: [
        { hopId: 'h1', origin: origin1, method: 'POST', pathAndQuery: '/v1/builds/b_1/preview', exchangeId: 'd1-h1' },
        { hopId: 'h2', origin: origin1, method: 'POST', pathAndQuery: '/v1/secrets/batch', exchangeId: 'd1-h2' },
        { hopId: 'h3', origin: origin1, method: 'POST', pathAndQuery: '/v1/releases/rel_1/publish', exchangeId: 'd1-h3' },
      ],
      claimTitle: 'Chain 1: build preview secret batch -> publish',
    }),
    secrets: [],
  })

  // Chain 2: 100% disjoint upstream path B -> SAME terminal POST /v1/releases/:id/publish (`dual_tenant_abac`)
  const c2 = persist({
    run,
    assignment: w1,
    script: '// chain 2',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-disjoint-2',
      terminalVulnClass: 'dual_tenant_abac',
      hops: [
        { hopId: 'h1', origin: origin1, method: 'POST', pathAndQuery: '/v1/automations', exchangeId: 'd2-h1' },
        { hopId: 'h2', origin: origin1, method: 'POST', pathAndQuery: '/v1/releases/rel_2/dispute', exchangeId: 'd2-h2' },
        { hopId: 'h3', origin: origin1, method: 'POST', pathAndQuery: '/v1/releases/rel_2/publish', exchangeId: 'd2-h3' },
      ],
      claimTitle: 'Chain 2: automation dispute -> publish',
    }),
    secrets: [],
  })

  // Chain 3 (R3-05 #6 negative): SAME agent-chosen chainId as c1 ('shared-agent-chain-name') on DIFFERENT terminal -> MUST stay separate!
  const c3 = persist({
    run,
    assignment: w1,
    script: '// chain 3 colliding chainId',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'shared-agent-chain-name',
      terminalVulnClass: 'temporal_revocation',
      hops: [
        { hopId: 'h1', origin: origin1, method: 'GET', pathAndQuery: '/v1/streams/shared', exchangeId: 'd3-h1' },
        { hopId: 'h2', origin: origin1, method: 'POST', pathAndQuery: '/v1/projects/p_1/transfer', exchangeId: 'd3-h2' },
        { hopId: 'h3', origin: origin1, method: 'GET', pathAndQuery: '/v1/repos/r_1/archive', exchangeId: 'd3-h3' },
      ],
      claimTitle: 'Chain 3: colliding agent-chosen chainId on distinct terminal',
    }),
    secrets: [],
  })

  // Chain 4: shares upstream hops with Chain 1, diverges to distinct terminal mutation
  const c4 = persist({
    run,
    assignment: w1,
    script: '// chain 4',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-divergent-4',
      terminalVulnClass: 'cryptographic_scope_replay',
      hops: [
        { hopId: 'h1', origin: origin1, method: 'POST', pathAndQuery: '/v1/builds/b_9/preview', exchangeId: 'd4-h1' },
        { hopId: 'h2', origin: origin1, method: 'POST', pathAndQuery: '/v1/secrets/batch', exchangeId: 'd4-h2' },
        { hopId: 'h3', origin: origin1, method: 'POST', pathAndQuery: '/v1/billing/payouts/pay_9/commit', exchangeId: 'd4-h3' },
      ],
      claimTitle: 'Chain 4: build preview secret batch -> billing commit',
    }),
    secrets: [],
  })

  // Chain 5 (R3-05 #5 negative): identical chain on a DIFFERENT loopback port (4716 vs 4715) -> MUST stay separate!
  const c5DiffPort = persist({
    run,
    assignment: w2,
    script: '// chain 5 different loopback port',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-port2-1',
      terminalVulnClass: 'dual_tenant_abac',
      hops: [
        { hopId: 'h1', origin: origin2, method: 'POST', pathAndQuery: '/v1/automations', exchangeId: 'd5-h1' },
        { hopId: 'h2', origin: origin2, method: 'POST', pathAndQuery: '/v1/releases/rel_9/dispute', exchangeId: 'd5-h2' },
        { hopId: 'h3', origin: origin2, method: 'POST', pathAndQuery: '/v1/releases/rel_9/publish', exchangeId: 'd5-h3' },
      ],
      claimTitle: 'Chain 5: same routes on distinct loopback port 4716',
    }),
    secrets: [],
  })

  // Chain 6 & 7 (R3-05 #7 negative): SAME terminal + DIFFERENT class + empty non-generic upstream (/login only) -> MUST stay separate!
  const c6EmptyUpA = persist({
    run,
    assignment: w1,
    script: '// chain 6 empty upstream abac',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-empty-up-abac',
      terminalVulnClass: 'dual_tenant_abac',
      hops: [
        { hopId: 'h1', origin: origin1, method: 'POST', pathAndQuery: '/api/login', exchangeId: 'd6-h1' },
        { hopId: 'h2', origin: origin1, method: 'POST', pathAndQuery: '/v1/vault/export', exchangeId: 'd6-h2' },
      ],
      claimTitle: 'Chain 6: login -> vault export (dual_tenant_abac)',
    }),
    secrets: [],
  })
  const c7EmptyUpB = persist({
    run,
    assignment: w1,
    script: '// chain 7 empty upstream econ',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-empty-up-econ',
      terminalVulnClass: 'economic_conservation',
      hops: [
        { hopId: 'h1', origin: origin1, method: 'POST', pathAndQuery: '/api/login', exchangeId: 'd7-h1' },
        { hopId: 'h2', origin: origin1, method: 'POST', pathAndQuery: '/v1/vault/export', exchangeId: 'd7-h2' },
      ],
      claimTitle: 'Chain 7: login -> vault export (economic_conservation)',
    }),
    secrets: [],
  })

  const uniqueIds = new Set([c1.findingId, c2.findingId, c3.findingId, c4.findingId, c5DiffPort.findingId, c6EmptyUpA.findingId, c7EmptyUpB.findingId])
  assert.equal(uniqueIds.size, 7, 'all 7 distinct chains must stay separate')
  assert.notEqual(c3.findingId, c1.findingId, 'R3-05 #6: colliding chainId on distinct terminals must stay separate')
  assert.notEqual(c5DiffPort.findingId, c2.findingId, 'R3-05 #5: distinct loopback ports must stay separate')
  assert.notEqual(c7EmptyUpB.findingId, c6EmptyUpA.findingId, 'R3-05 #7: same-terminal different-class chains with empty non-generic upstream must stay separate')

  const active = filterActiveFindings(storage.runDetail(runId).findings as Finding[]).filter(f => f.status === 'confirmed')
  assert.equal(active.length, 7, 'all 7 distinct chains must remain active confirmed findings')
})

// ---------------------------------------------------------------------------
// 4. Grader duplicate-of-confirmed-chain attribution & R3-05 #1-#3 strictness
// ---------------------------------------------------------------------------

test('4. gradeRun avoids vulnerable-mode duplicate twinFP misattribution, enforces R3-05 #1-#3 strictness on superseded/hardened/decoy/self-declared chainId', async () => {
  const vuln = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'grey-box', fastLab: true })
  const hardened = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'hardened', fastLab: true })
  const twinD2 = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'grey-box', twin: 'PG-D2', fastLab: true })
  try {
    const p = routePrefixOf(vuln)
    const pgC2Receipt1: ProductSubmittedCompositeProof = {
      findingId: 'pg-c2-f1',
      chainId: 'chain-generic-settlement-1',
      terminalVulnClass: 'economic_conservation',
      hopCount: 4,
      replayMode: 'fresh_clean_replay',
      confirmed: true,
      attackerProvenanceValid: true,
      receipt: {
        hops: [
          { hopId: 'h1', target: { method: 'PATCH', pathAndQuery: `${p}/invoice-templates/tpl_001` } },
          { hopId: 'h2', target: { method: 'POST', pathAndQuery: `${p}/invoices/inv_001/render` } },
          { hopId: 'h3', target: { method: 'GET', pathAndQuery: `${p}/jobs/job_001/trace` } },
          { hopId: 'h4', target: { method: 'POST', pathAndQuery: `${p}/webhooks/settlement` } },
        ],
        causalEdges: [{ kind: 'async_pivot_binding' }, { kind: 'value_binding' }, { kind: 'derived_crypto_binding' }],
        terminalImpact: { terminalHopId: 'h4' },
      },
      verification: {
        terminalEndpoint: `${p}/webhooks/settlement`,
        terminalOracleFamily: 'economic_conservation',
      },
    }
    const pgC2Finding1: ProductSubmittedFinding = {
      id: 'pg-c2-f1',
      findingId: 'pg-c2-f1',
      vulnClass: 'economic_conservation',
      endpoints: [
        { method: 'PATCH', path: `${p}/invoice-templates/tpl_001` },
        { method: 'POST', path: `${p}/invoices/inv_001/render` },
        { method: 'GET', path: `${p}/jobs/job_001/trace` },
        { method: 'POST', path: `${p}/webhooks/settlement` },
      ],
      status: 'confirmed',
    }
    const pgC2Finding2Dup: ProductSubmittedFinding = {
      id: 'pg-c2-f2-dup',
      findingId: 'pg-c2-f2-dup',
      vulnClass: 'dual_tenant_abac',
      endpoints: [
        { method: 'POST', path: `${p}/invoices/inv_002/render` },
        { method: 'POST', path: `${p}/webhooks/settlement` },
      ],
      status: 'confirmed',
    }
    const pgC2Receipt2Dup: ProductSubmittedCompositeProof = {
      ...pgC2Receipt1,
      findingId: 'pg-c2-f2-dup',
      chainId: 'chain-generic-settlement-2',
      terminalVulnClass: 'dual_tenant_abac',
    }

    // (a) Vulnerable mode with PG-C2 confirmed + verified Mode-A duplicate receipt: NOT misclassified as
    //     hardenedTwinDecoyFp, but still counted as unmatchedFalsePositives=1 so precision is never weakened!
    const dupCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [pgC2Finding1, pgC2Finding2Dup],
      compositeReceipts: [pgC2Receipt1, pgC2Receipt2Dup],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, ['PG-C2']),
      mode: 'grey-box',
    })
    assert.equal(dupCard.chains.find((c) => c.chainId === 'PG-C2')?.twoSideConfirmed, true)
    assert.equal(dupCard.hardenedTwins.find((t) => t.twinId === 'PG-D2')?.falsePositive, false)
    assert.equal(dupCard.hardenedTwinDecoyFps, 0, 'verified Mode-A duplicate of confirmed base chain must not inflate hardenedTwinDecoyFps')
    assert.equal(dupCard.unmatchedFalsePositives, 1, 'unsuperseded duplicate remains a strict unmatched FP')
    assert.equal(dupCard.precision, 0.5)

    // (b) Vulnerable mode with PG-C2 confirmed + related superseded partial pointing to explicit status:'confirmed' winner -> precision=1.0
    const supersededPartial: ProductSubmittedFinding = {
      id: 'pg-c2-partial-sup',
      findingId: 'pg-c2-partial-sup',
      vulnClass: 'dual_tenant_abac',
      endpoints: [{ method: 'POST', path: `${p}/invoices/inv_003/render` }],
      status: 'confirmed',
      supersededByFindingId: 'pg-c2-f1',
    }
    const supersededCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [pgC2Finding1, supersededPartial],
      compositeReceipts: [pgC2Receipt1],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, ['PG-C2']),
      mode: 'grey-box',
    })
    assert.equal(supersededCard.hardenedTwinDecoyFps, 0)
    assert.equal(supersededCard.unmatchedFalsePositives, 0)
    assert.equal(supersededCard.precision, 1)

    // (c) R3-05 #2: unrelated FP pointing supersededByFindingId at confirmed winner pg-c2-f1 MUST NOT vanish!
    const unrelatedSuperseded: ProductSubmittedFinding = {
      id: 'unrelated-fp-sup',
      findingId: 'unrelated-fp-sup',
      vulnClass: 'sqli',
      endpoints: [{ method: 'GET', path: `${p}/unrelated/admin/report` }],
      status: 'confirmed',
      supersededByFindingId: 'pg-c2-f1',
    }
    const unrelatedSupCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [pgC2Finding1, unrelatedSuperseded],
      compositeReceipts: [pgC2Receipt1],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, ['PG-C2']),
      mode: 'grey-box',
    })
    assert.equal(unrelatedSupCard.unmatchedFalsePositives, 1, 'R3-05 #2: unrelated FP cannot vanish by pointing supersededByFindingId at a confirmed TP')

    // (d) R3-05 #2: winner with omitted `status` (undefined) MUST NOT suppress a superseded finding!
    const { status: _omitted, ...winnerNoStatus } = pgC2Finding1
    const noStatusWinnerCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [winnerNoStatus, supersededPartial],
      compositeReceipts: [pgC2Receipt1],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, ['PG-C2']),
      mode: 'grey-box',
    })
    assert.equal(noStatusWinnerCard.hardenedTwinDecoyFps, 1, 'R3-05 #2: winner without explicit status==="confirmed" must not suppress superseded finding')

    // (e) R3-05 #3: unverified finding listing BOTH decoy hop AND base terminal (without confirmed Mode-A receipt)
    //     OR self-declaring `chainId: 'PG-C2'` MUST STILL trigger PG-D2 hardenedTwinDecoyFp!
    const selfDeclaredBypass: ProductSubmittedFinding = {
      id: 'pg-d2-self-declared',
      findingId: 'pg-d2-self-declared',
      chainId: 'PG-C2',
      vulnClass: 'dual_tenant_abac',
      endpoints: [
        { method: 'POST', path: `${p}/invoices/inv_088/render` },
        { method: 'POST', path: `${p}/webhooks/settlement` },
      ],
      status: 'confirmed',
    }
    const selfDeclaredCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [pgC2Finding1, selfDeclaredBypass],
      compositeReceipts: [pgC2Receipt1],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, ['PG-C2']),
      mode: 'grey-box',
    })
    assert.equal(selfDeclaredCard.hardenedTwins.find((t) => t.twinId === 'PG-D2')?.falsePositive, true)
    assert.equal(selfDeclaredCard.hardenedTwinDecoyFps, 1, 'R3-05 #3: self-declared chainId / unverified finding listing decoy + base terminal must still count as hardenedTwinDecoyFp')

    // (f) Dangling or non-confirmed supersededByFindingId MUST NEVER hide an FP
    const danglingSup: ProductSubmittedFinding = {
      id: 'pg-d2-dangling-sup',
      findingId: 'pg-d2-dangling-sup',
      vulnClass: 'dual_tenant_abac',
      endpoints: [{ method: 'POST', path: `${p}/invoices/inv_004/render` }],
      status: 'confirmed',
      supersededByFindingId: 'nonexistent-finding-id',
    }
    const danglingCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [pgC2Finding1, danglingSup],
      compositeReceipts: [pgC2Receipt1],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, ['PG-C2']),
      mode: 'grey-box',
    })
    assert.equal(danglingCard.hardenedTwinDecoyFps, 1, 'dangling supersededByFindingId must not hide decoy-only FP')

    // (g) Genuine decoy-only FP STILL triggers PG-D2 even when PG-C2 is confirmed
    const decoyOnlyFinding: ProductSubmittedFinding = {
      id: 'pg-d2-decoy-only',
      findingId: 'pg-d2-decoy-only',
      vulnClass: 'forged_settlement',
      endpoints: [{ method: 'POST', path: `${p}/invoices/inv_099/render` }],
      status: 'confirmed',
    }
    const decoyOnlyCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [pgC2Finding1, decoyOnlyFinding],
      compositeReceipts: [pgC2Receipt1],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, ['PG-C2']),
      mode: 'grey-box',
    })
    assert.equal(decoyOnlyCard.hardenedTwins.find((t) => t.twinId === 'PG-D2')?.falsePositive, true)
    assert.equal(decoyOnlyCard.hardenedTwinDecoyFps, 1, 'genuine decoy-only FP must stay 100% strict even when base chain is confirmed')

    // (h) R3-05 #1: Real isTwinMode=true (hardened mode AND PG-D2 twin mode) MUST skip supersededByFindingId filter completely!
    const hardenedWithSuperseded = gradeRun({
      groundTruth: hardened.groundTruth,
      findings: [pgC2Finding1, supersededPartial],
      compositeReceipts: [pgC2Receipt1],
      oracleEvents: [],
      oracleExport: hardened.export(),
      mode: 'grey-box',
    })
    assert.equal(hardenedWithSuperseded.hardenedTwinDecoyFps, 2, 'R3-05 #1: hardened mode must NOT drop supersededByFindingId findings')
    assert.equal(hardenedWithSuperseded.precision, 0)

    const twinWithSuperseded = gradeRun({
      groundTruth: twinD2.groundTruth,
      findings: [pgC2Finding1, supersededPartial],
      compositeReceipts: [pgC2Receipt1],
      oracleEvents: [],
      oracleExport: twinD2.export(),
      mode: 'grey-box',
    })
    assert.equal(twinWithSuperseded.hardenedTwins.find((t) => t.twinId === 'PG-D2')?.falsePositive, true)
    assert.equal(twinWithSuperseded.hardenedTwinDecoyFps, 2, 'R3-05 #1: twin mode must NOT drop supersededByFindingId findings')
    assert.equal(twinWithSuperseded.precision, 0)
  } finally {
    await vuln.stop()
    await hardened.stop()
    await twinD2.stop()
  }
})
