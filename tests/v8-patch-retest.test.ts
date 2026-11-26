/**
 * v8 Stream B — Multi-Hop CompositeProofReceipt DAG Patch-Retest (`patchBrokeHopId`) tests.
 *
 * Covers all 4 honest verdicts on a 4-hop CompositeProofReceipt DAG:
 *  1. Patched at Hop 3 (HTTP 403 block AND sanitized 200 non-emission) while Hops 1–2 remain benign
 *     -> 'fixed' with `patchBrokeHopId === 'hop-3'` and `benignPrefixHops: ['hop-1', 'hop-2']`.
 *  2. Patched at terminal Hop 4 (HTTP 403 block AND 200 invariant-preserved terminal oracle failure)
 *     -> 'fixed' with `patchBrokeHopId === 'hop-4'` and `benignPrefixHops: ['hop-1', 'hop-2', 'hop-3']`.
 *  3. Unpatched target -> 'still_vulnerable' (full DAG confirmed via `verifyCompositeReceipt()`).
 *  4. Transport timeout / HTTP 503 / HTTP 429 / auth setup failure / tampered host signature
 *     -> 'inconclusive' (strictly fail-closed; never falsely claims 'fixed').
 *  5. Pre-chain setup or hop route/schema drift -> 'precondition_changed' (never falsely 'fixed').
 *  6. Out-of-order input hops still execute strictly in topological order; fresh replayed IDs remap cleanly;
 *     secret redaction, SHA-256 tamper-evident proof integrity, portable export projection,
 *     OSS M4 closure grading (`>= 80%`), and anti-contamination lint.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { sha256Hex, signHostRecord } from '../src/server/composite-receipt.ts'
import type {
  CompositeProofReceipt,
  HostAsyncPollRecord,
  HostSignedTranscript,
  HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import type { ImpactStep } from '../src/server/proof-receipt.ts'
import {
  retestCompositeChainPatch,
  summarizeCompositePatchClosure,
  toPortablePatchRetestProof,
  verifyCompositePatchRetestProofIntegrity,
} from '../src/server/patch-workflow.ts'
import type {
  CompositeHopReplayContext,
  CompositePatchReplayRunner,
} from '../src/server/patch-workflow.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const ORIGIN_API = 'https://api.example.test'
const ORIGIN_WORKER = 'https://worker.example.test'
const SIGNING_KEY = 'test-v8-patch-retest-signing-key-hmac'

const CAP_HOP1 = 'cap:hop-1:org_directory_token'
const CAP_HOP2 = 'cap:hop-2:template_job_handle'
const CAP_HOP3 = 'cap:hop-3:signing_salt_handle'
const CAP_HOP4_DERIVED = 'cap:hop-4:signed_settlement_sig'
const CORR_ID = 'corr-async-export-4042'

function makeStep(
  partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>,
): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: partial.actor ?? {
      handle: 'member_a',
      role: 'member',
      tenant: 'org-a',
      auth: 'bearer',
      sameSite: null,
    },
    ...(partial.route !== undefined ? { route: partial.route } : {}),
    ...(partial.pathAndQuery !== undefined ? { pathAndQuery: partial.pathAndQuery } : {}),
    ...(partial.json !== undefined ? { json: partial.json } : {}),
    ...(partial.body !== undefined ? { body: partial.body } : {}),
    ...(partial.requestJson !== undefined ? { requestJson: partial.requestJson } : {}),
    ...(partial.requestHeaders !== undefined ? { requestHeaders: partial.requestHeaders } : {}),
    ...(partial.responseHeaders !== undefined ? { responseHeaders: partial.responseHeaders } : {}),
    ...(partial.evidenceRole !== undefined ? { evidenceRole: partial.evidenceRole } : {}),
  }
}

function signedEntry(
  exchangeId: string,
  step: ImpactStep,
  extra: Partial<HostTranscriptEntry> = {},
  key = SIGNING_KEY,
): HostTranscriptEntry {
  const base: HostTranscriptEntry = {
    exchangeId,
    step,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
  return { ...base, hostSignature: signHostRecord(base, key) }
}

function signedPoll(
  poll: Omit<HostAsyncPollRecord, 'hostSignature'>,
  key = SIGNING_KEY,
): HostAsyncPollRecord {
  return { ...poll, hostSignature: signHostRecord(poll, key) }
}

/**
 * 4-hop realistic causal DAG:
 *   hop-1 (benign directory lookup)
 *     --[value_binding: CAP_HOP1]-->
 *   hop-2 (benign template job trigger)
 *     --[async_pivot_binding: CORR_ID / poll_convergence]-->
 *   hop-3 (async worker readback exposing signing material CAP_HOP3)
 *     --[derived_crypto_binding: CAP_HOP3 -> CAP_HOP4_DERIVED]-->
 *   hop-4 (terminal signed action executing unauthorized transfer)
 */
function buildFourHopReceipt(options?: { scrambleHopOrder?: boolean }): CompositeProofReceipt {
  const hops: CompositeProofReceipt['hops'] = [
    {
      hopId: 'hop-1',
      surface: 'http',
      target: { origin: ORIGIN_API, method: 'GET', pathAndQuery: '/api/v1/org/directory' },
      exchangeIds: ['ex-1'],
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: 'Benign directory lookup yields org routing handle',
      producedCapabilities: [CAP_HOP1],
      consumedCapabilities: [],
    },
    {
      hopId: 'hop-2',
      surface: 'http',
      target: { origin: ORIGIN_API, method: 'POST', pathAndQuery: '/api/v1/reports/render' },
      exchangeIds: ['ex-2'],
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: 'Benign report render schedules async job with correlation ID',
      producedCapabilities: [CAP_HOP2],
      consumedCapabilities: [CAP_HOP1],
    },
    {
      hopId: 'hop-3',
      surface: 'async_job',
      target: { origin: ORIGIN_WORKER, method: 'GET', pathAndQuery: `/internal/jobs/${CORR_ID}/log` },
      exchangeIds: ['ex-3'],
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: 'Async worker log leaks internal signing material handle',
      producedCapabilities: [CAP_HOP3],
      consumedCapabilities: [CAP_HOP2],
    },
    {
      hopId: 'hop-4',
      surface: 'webhook',
      target: { origin: ORIGIN_API, method: 'POST', pathAndQuery: '/api/v1/settlements/execute' },
      exchangeIds: ['ex-4'],
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: 'Derived HMAC signature authorizes cross-tenant settlement transfer',
      producedCapabilities: [],
      consumedCapabilities: [CAP_HOP3],
    },
  ]

  return {
    chainId: 'chain-4hop-retest-01',
    terminalVulnClass: 'cryptographic_scope_replay',
    hops: options?.scrambleHopOrder ? [hops[3]!, hops[1]!, hops[0]!, hops[2]!] : hops,
    causalEdges: [
      {
        kind: 'value_binding',
        fromHopId: 'hop-1',
        toHopId: 'hop-2',
        capabilityHandle: CAP_HOP1,
      },
      {
        kind: 'async_pivot_binding',
        fromHopId: 'hop-2',
        toHopId: 'hop-3',
        correlationId: CORR_ID,
        channel: 'poll_convergence',
        pollRecordId: 'poll-2-3',
      },
      {
        kind: 'derived_crypto_binding',
        fromHopId: 'hop-3',
        toHopId: 'hop-4',
        sourceCapabilityId: CAP_HOP3,
        derivedCapabilityId: CAP_HOP4_DERIVED,
        alg: 'hmac-sha256',
      },
    ],
    terminalImpact: {
      terminalHopId: 'hop-4',
      summary: 'Unauthorized settlement transfer executed via forged derived signature',
      claimedImpact: 'Unauthorized settlement transfer executed via forged derived signature',
      preChainControlExchangeIds: [],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
}

function makeUnpatchedRunner(options?: {
  freshIds?: boolean
  onHop?: (ctx: CompositeHopReplayContext) => void
  signingKey?: string
}): CompositePatchReplayRunner {
  const key = options?.signingKey ?? SIGNING_KEY
  const prefix = options?.freshIds ? 'retest-' : ''
  return {
    replayHop(ctx) {
      options?.onHop?.(ctx)
      if (ctx.hop.hopId === 'hop-1') {
        return {
          entries: [
            signedEntry(`${prefix}ex-1`, makeStep({ id: `${prefix}ex-1`, arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/org/directory', json: { org: 'org-a' } }), {
              timestampMs: 1000,
              actorPersona: 'member_a',
              emittedCapabilities: [CAP_HOP1],
            }, key),
          ],
        }
      }
      if (ctx.hop.hopId === 'hop-2') {
        return {
          entries: [
            signedEntry(`${prefix}ex-2`, makeStep({ id: `${prefix}ex-2`, arm: 'probe', method: 'POST', status: 202, pathAndQuery: '/api/v1/reports/render', json: { jobId: CORR_ID } }), {
              timestampMs: 2000,
              actorPersona: 'member_a',
              consumedCapabilities: [CAP_HOP1],
              emittedCapabilities: [CAP_HOP2],
              correlationIds: [CORR_ID],
            }, key),
          ],
        }
      }
      if (ctx.hop.hopId === 'hop-3') {
        return {
          entries: [
            signedEntry(`${prefix}ex-3`, makeStep({ id: `${prefix}ex-3`, arm: 'probe', method: 'GET', status: 200, pathAndQuery: `/internal/jobs/${CORR_ID}/log`, json: { status: 'done' } }), {
              timestampMs: 3000,
              actorPersona: 'member_a',
              consumedCapabilities: [CAP_HOP2],
              emittedCapabilities: [CAP_HOP3],
              correlationIds: [CORR_ID],
            }, key),
          ],
          asyncPollRecords: [
            signedPoll({
              id: `${prefix}poll-2-3`,
              triggerExchangeId: `${prefix}ex-2`,
              tTriggerMs: 2000,
              tObservedMs: 2800,
              converged: true,
              correlationIds: [CORR_ID],
              emittedCapabilities: [CAP_HOP3],
            }, key),
          ],
        }
      }
      // hop-4
      return {
        entries: [
          signedEntry(`${prefix}ex-4`, makeStep({ id: `${prefix}ex-4`, arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/settlements/execute', json: { transferred: true, amount: 5000 } }), {
            timestampMs: 4000,
            actorPersona: 'member_a',
            consumedCapabilities: [CAP_HOP3],
            cryptoAttestations: [{
              derivedFromCapabilityId: CAP_HOP3,
              derivedCapabilityId: CAP_HOP4_DERIVED,
              alg: 'hmac-sha256',
              artifactDigest: sha256Hex('settlement-payload-v1'),
              timestampMs: 3500,
            }],
          }, key),
        ],
      }
    },
  }
}

// ============================================================================
// 0. Anti-Contamination Lint
// ============================================================================

test('src/server/patch-workflow.ts contains zero benchmark literals', () => {
  const src = readFileSync(join(repoRoot, 'src/server/patch-workflow.ts'), 'utf8')
  const forbidden = [
    /\bpaygrid\b/i,
    /\bshipforge\b/i,
    /\bnexusiam\b/i,
    /\bconnecthub\b/i,
    /\b(?:PG|SF|NX|CH)-C\d+\b/,
    /vault\.internal/i,
    /registry\.internal/i,
    /billing\.internal/i,
    /mh_fake_/i,
  ]
  for (const re of forbidden) {
    assert.equal(re.test(src), false, `Benchmark literal matched ${re} in src/server/patch-workflow.ts`)
  }
})

// ============================================================================
// 1. Verdict: 'fixed' — Patched at Hop 3 (while Hops 1–2 remain benign)
// ============================================================================

test('4-hop DAG patched at Hop 3 (HTTP 403 block) while Hops 1–2 remain benign -> fixed at hop-3', async () => {
  const receipt = buildFourHopReceipt()
  const executedHops: string[] = []
  const baseRunner = makeUnpatchedRunner({ onHop: ctx => executedHops.push(ctx.hop.hopId) })

  const runner: CompositePatchReplayRunner = {
    replayHop(ctx) {
      if (ctx.hop.hopId === 'hop-3') {
        executedHops.push('hop-3')
        return {
          entries: [
            signedEntry('ex-3', makeStep({ id: 'ex-3', arm: 'probe', method: 'GET', status: 403, pathAndQuery: `/internal/jobs/${CORR_ID}/log`, json: { error: 'forbidden' } }), {
              timestampMs: 3000,
              actorPersona: 'member_a',
              consumedCapabilities: [CAP_HOP2],
            }),
          ],
          reason: 'Worker log endpoint now enforces internal-only authorization (HTTP 403)',
        }
      }
      return baseRunner.replayHop(ctx)
    },
  }

  const proof = await retestCompositeChainPatch({
    receipt,
    runner,
    verifyOptions: { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY },
    targetRevision: 'commit-fix-hop3',
    patchId: 'patch-001',
    now: () => 1_700_000_010_000,
  })

  assert.equal(proof.verdict, 'fixed')
  assert.equal(proof.patchClosed, true)
  assert.equal(proof.patchBrokeHopId, 'hop-3')
  assert.deepEqual(proof.benignPrefixHops, ['hop-1', 'hop-2'])
  assert.deepEqual(proof.brokeCausalEdge, {
    edgeIndex: 1,
    kind: 'async_pivot_binding',
    fromHopId: 'hop-2',
    toHopId: 'hop-3',
  })
  assert.match(proof.brokeReason ?? '', /403|authorization/i)
  // Downstream hop-4 must not be executed once hop-3 breaks cleanly.
  assert.deepEqual(executedHops, ['hop-1', 'hop-2', 'hop-3'])
  assert.equal(proof.hopResults.find(h => h.hopId === 'hop-4')?.outcome, 'skipped_after_break')
  assert.equal(verifyCompositePatchRetestProofIntegrity(proof), true)

  // Tampering with patchBrokeHopId MUST fail digest verification.
  assert.equal(
    verifyCompositePatchRetestProofIntegrity({ ...proof, patchBrokeHopId: 'hop-4' }),
    false,
  )
})

test('4-hop DAG patched at Hop 3 (HTTP 200 sanitized — stops leaking capability) -> fixed at hop-3', async () => {
  const receipt = buildFourHopReceipt()
  const executedHops: string[] = []
  const baseRunner = makeUnpatchedRunner({ onHop: ctx => executedHops.push(ctx.hop.hopId) })

  const runner: CompositePatchReplayRunner = {
    replayHop(ctx) {
      if (ctx.hop.hopId === 'hop-3') {
        executedHops.push('hop-3')
        // Patched worker returns 200 OK with redacted logs — CAP_HOP3 is no longer emitted!
        return {
          entries: [
            signedEntry('ex-3', makeStep({ id: 'ex-3', arm: 'probe', method: 'GET', status: 200, pathAndQuery: `/internal/jobs/${CORR_ID}/log`, json: { status: 'done', detail: '[redacted]' } }), {
              timestampMs: 3000,
              actorPersona: 'member_a',
              consumedCapabilities: [CAP_HOP2],
              emittedCapabilities: [],
              correlationIds: [CORR_ID],
            }),
          ],
          asyncPollRecords: [
            signedPoll({
              id: 'poll-2-3',
              triggerExchangeId: 'ex-2',
              tTriggerMs: 2000,
              tObservedMs: 2800,
              converged: true,
              correlationIds: [CORR_ID],
              emittedCapabilities: [],
            }),
          ],
        }
      }
      return baseRunner.replayHop(ctx)
    },
  }

  const proof = await retestCompositeChainPatch({
    receipt,
    runner,
    verifyOptions: { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY },
  })

  assert.equal(proof.verdict, 'fixed')
  assert.equal(proof.patchClosed, true)
  assert.equal(proof.patchBrokeHopId, 'hop-3')
  assert.deepEqual(proof.benignPrefixHops, ['hop-1', 'hop-2'])
  assert.deepEqual(proof.brokeCausalEdge, {
    edgeIndex: 2,
    kind: 'derived_crypto_binding',
    fromHopId: 'hop-3',
    toHopId: 'hop-4',
  })
  assert.match(proof.brokeReason ?? '', /no longer emits signing material/i)
  assert.deepEqual(executedHops, ['hop-1', 'hop-2', 'hop-3'])
  assert.equal(verifyCompositePatchRetestProofIntegrity(proof), true)
})

// ============================================================================
// 2. Verdict: 'fixed' — Patched at Terminal Hop 4
// ============================================================================

test('4-hop DAG patched at terminal Hop 4 (HTTP 403 block) -> fixed at hop-4', async () => {
  const receipt = buildFourHopReceipt()
  const baseRunner = makeUnpatchedRunner()

  const runner: CompositePatchReplayRunner = {
    replayHop(ctx) {
      if (ctx.hop.hopId === 'hop-4') {
        return {
          entries: [
            signedEntry('ex-4', makeStep({ id: 'ex-4', arm: 'probe', method: 'POST', status: 403, pathAndQuery: '/api/v1/settlements/execute', json: { error: 'scope_mismatch' } }), {
              timestampMs: 4000,
              actorPersona: 'member_a',
              consumedCapabilities: [CAP_HOP3],
            }),
          ],
          reason: 'Settlement webhook now binds HMAC verification to tenant and route scope (HTTP 403)',
        }
      }
      return baseRunner.replayHop(ctx)
    },
  }

  const proof = await retestCompositeChainPatch({
    receipt,
    runner,
    verifyOptions: { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY },
  })

  assert.equal(proof.verdict, 'fixed')
  assert.equal(proof.patchClosed, true)
  assert.equal(proof.patchBrokeHopId, 'hop-4')
  assert.deepEqual(proof.benignPrefixHops, ['hop-1', 'hop-2', 'hop-3'])
  assert.deepEqual(proof.brokeCausalEdge, {
    edgeIndex: 2,
    kind: 'derived_crypto_binding',
    fromHopId: 'hop-3',
    toHopId: 'hop-4',
  })
  assert.match(proof.brokeReason ?? '', /403|scope/i)
  assert.equal(verifyCompositePatchRetestProofIntegrity(proof), true)
})

test('4-hop DAG patched at terminal Hop 4 (HTTP 200 no-op; terminal oracle rejects) -> fixed at hop-4', async () => {
  const receipt = buildFourHopReceipt()
  const baseRunner = makeUnpatchedRunner()

  const runner: CompositePatchReplayRunner = {
    replayHop(ctx) {
      if (ctx.hop.hopId === 'hop-4') {
        return {
          entries: [
            signedEntry('ex-4', makeStep({ id: 'ex-4', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/settlements/execute', json: { transferred: false, reason: 'ignored_unscoped_sig' } }), {
              timestampMs: 4000,
              actorPersona: 'member_a',
              consumedCapabilities: [CAP_HOP3],
              cryptoAttestations: [{
                derivedFromCapabilityId: CAP_HOP3,
                derivedCapabilityId: CAP_HOP4_DERIVED,
                alg: 'hmac-sha256',
                artifactDigest: sha256Hex('settlement-payload-v1'),
                timestampMs: 3500,
              }],
            }),
          ],
        }
      }
      return baseRunner.replayHop(ctx)
    },
  }

  const proof = await retestCompositeChainPatch({
    receipt,
    runner,
    verifyOptions: {
      attackerPersonas: ['member_a'],
      signingKey: SIGNING_KEY,
      verifyTerminalImpact(_rcpt, transcript: HostSignedTranscript) {
        const term = (transcript.entries ?? []).find(e => e.exchangeId === 'ex-4')
        const transferred = (term?.step.json as { transferred?: boolean } | undefined)?.transferred === true
        return transferred
          ? { confirmed: true, reason: 'Unauthorized settlement transfer occurred.' }
          : { confirmed: false, reason: 'Settlement invariant preserved: transferred=false after patch.' }
      },
    },
  })

  assert.equal(proof.verdict, 'fixed')
  assert.equal(proof.patchClosed, true)
  assert.equal(proof.patchBrokeHopId, 'hop-4')
  assert.deepEqual(proof.benignPrefixHops, ['hop-1', 'hop-2', 'hop-3'])
  assert.equal(proof.brokeCausalEdge, null)
  assert.match(proof.brokeReason ?? '', /invariant preserved/i)
  assert.equal(proof.compositeVerification?.failedStage, 'terminal_impact')
  assert.equal(verifyCompositePatchRetestProofIntegrity(proof), true)
})

// ============================================================================
// 3. Verdict: 'still_vulnerable' — Unpatched Target (with topological sort + fresh ID remapping)
// ============================================================================

test('4-hop DAG on unpatched target -> still_vulnerable, executes strictly in topological order & remaps fresh IDs', async () => {
  const receipt = buildFourHopReceipt({ scrambleHopOrder: true })
  const executedOrder: string[] = []
  const runner = makeUnpatchedRunner({
    freshIds: true,
    onHop: ctx => executedOrder.push(ctx.hop.hopId),
  })

  const proof = await retestCompositeChainPatch({
    receipt,
    runner,
    verifyOptions: {
      attackerPersonas: ['member_a'],
      signingKey: SIGNING_KEY,
      verifyTerminalImpact(_rcpt, transcript) {
        const term = (transcript.entries ?? []).find(e => e.exchangeId === 'retest-ex-4')
        const ok = (term?.step.json as { transferred?: boolean } | undefined)?.transferred === true
        return { confirmed: ok, reason: ok ? 'Unauthorized settlement transfer reproduced.' : 'Blocked.' }
      },
    },
  })

  assert.deepEqual(executedOrder, ['hop-1', 'hop-2', 'hop-3', 'hop-4'])
  assert.deepEqual(proof.topoOrder, ['hop-1', 'hop-2', 'hop-3', 'hop-4'])
  assert.equal(proof.verdict, 'still_vulnerable')
  assert.equal(proof.patchClosed, false)
  assert.equal(proof.patchBrokeHopId, null)
  assert.equal(proof.brokeCausalEdge, null)
  assert.equal(proof.brokeReason, null)
  assert.deepEqual(proof.benignPrefixHops, [])
  assert.equal(proof.compositeVerification?.confirmed, true)
  assert.equal(proof.compositeVerification?.verifiedEdges.length, 3)
  assert.deepEqual(proof.exchangeIds, ['retest-ex-1', 'retest-ex-2', 'retest-ex-3', 'retest-ex-4'])
  assert.equal(verifyCompositePatchRetestProofIntegrity(proof), true)

  const portable = toPortablePatchRetestProof(proof)
  assert.equal(portable.verdict, 'reproduced')
  assert.equal(portable.compositeVerdict, 'still_vulnerable')
  assert.equal(portable.patchBrokeHopId, null)
})

// ============================================================================
// 4. Verdict: 'inconclusive' — Transport Timeout / 503 / Auth Setup / Bad Signature (Fail Closed!)
// ============================================================================

test('4-hop DAG with HTTP 503 during Hop 3 replay -> inconclusive (NEVER falsely fixed)', async () => {
  const receipt = buildFourHopReceipt()
  const baseRunner = makeUnpatchedRunner()

  const runner: CompositePatchReplayRunner = {
    replayHop(ctx) {
      if (ctx.hop.hopId === 'hop-3') {
        // Even if a caller accidentally passes outcome:'blocked' alongside HTTP 503,
        // the retest verifier MUST fail closed to 'inconclusive'.
        return {
          outcome: 'blocked',
          entries: [
            signedEntry('ex-3', makeStep({ id: 'ex-3', arm: 'probe', method: 'GET', status: 503, pathAndQuery: `/internal/jobs/${CORR_ID}/log`, body: 'Service Unavailable' }), {
              timestampMs: 3000,
              actorPersona: 'member_a',
            }),
          ],
        }
      }
      return baseRunner.replayHop(ctx)
    },
  }

  const proof = await retestCompositeChainPatch({
    receipt,
    runner,
    verifyOptions: { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY },
  })

  assert.equal(proof.verdict, 'inconclusive')
  assert.equal(proof.patchClosed, false)
  assert.equal(proof.patchBrokeHopId, null)
  assert.equal(proof.brokeCausalEdge, null)
  assert.equal(proof.brokeReason, null)
  assert.match(proof.summary, /503|inconclusive/i)
  assert.equal(verifyCompositePatchRetestProofIntegrity(proof), true)
})

test('4-hop DAG with network timeout exception during Hop 3 replay -> inconclusive (NEVER falsely fixed)', async () => {
  const receipt = buildFourHopReceipt()
  const baseRunner = makeUnpatchedRunner()

  const runner: CompositePatchReplayRunner = {
    async replayHop(ctx) {
      if (ctx.hop.hopId === 'hop-3') {
        const err = new Error('connect ETIMEDOUT 127.0.0.1:8443') as Error & { code: string }
        err.code = 'ETIMEDOUT'
        throw err
      }
      return baseRunner.replayHop(ctx)
    },
  }

  const proof = await retestCompositeChainPatch({
    receipt,
    runner,
    verifyOptions: { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY },
  })

  assert.equal(proof.verdict, 'inconclusive')
  assert.equal(proof.patchClosed, false)
  assert.equal(proof.patchBrokeHopId, null)
  assert.equal(proof.hopResults.find(h => h.hopId === 'hop-3')?.outcome, 'transport_error')
  assert.equal(proof.hopResults.find(h => h.hopId === 'hop-3')?.errorCode, 'ETIMEDOUT')
  assert.match(proof.summary, /ETIMEDOUT/i)
  assert.equal(verifyCompositePatchRetestProofIntegrity(proof), true)
})

test('4-hop DAG with auth setup failure or tampered host signature -> inconclusive (fail closed)', async () => {
  const receipt = buildFourHopReceipt()

  // Auth setup failure in preparePreconditions
  const authFailProof = await retestCompositeChainPatch({
    receipt,
    runner: {
      preparePreconditions: () => ({
        status: 'auth_setup_failed',
        reason: 'Could not mint test persona session cookie (IdP unreachable)',
        errorCode: 'AUTH_SETUP_FAILED',
      }),
      replayHop: () => { throw new Error('Should not replay hops when auth setup failed') },
    },
    verifyOptions: { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY },
  })
  assert.equal(authFailProof.verdict, 'inconclusive')
  assert.equal(authFailProof.patchClosed, false)
  assert.equal(authFailProof.patchBrokeHopId, null)

  // Tampered host signature on hop-2 (wrong key)
  const badSigProof = await retestCompositeChainPatch({
    receipt,
    runner: makeUnpatchedRunner({ signingKey: 'wrong-key-not-host-key' }),
    verifyOptions: { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY },
  })
  assert.equal(badSigProof.verdict, 'inconclusive')
  assert.equal(badSigProof.patchClosed, false)
  assert.equal(badSigProof.patchBrokeHopId, null)
  assert.match(badSigProof.summary, /signature/i)
})

// ============================================================================
// 5. Verdict: 'precondition_changed' — Target Route / Schema Drift
// ============================================================================

test('4-hop DAG when pre-chain setup or hop detects route/schema change -> precondition_changed', async () => {
  const receipt = buildFourHopReceipt()

  // Pre-chain setup detects route/schema drift before Hop 1 runs.
  const setupDrift = await retestCompositeChainPatch({
    receipt,
    runner: {
      preparePreconditions: () => ({
        status: 'precondition_changed',
        reason: 'POST /api/v1/reports/render schema moved to /api/v2/exports with required workspaceUuid field',
        httpStatus: 404,
      }),
      replayHop: () => { throw new Error('Should not execute hops after precondition_changed') },
    },
    verifyOptions: { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY },
  })

  assert.equal(setupDrift.verdict, 'precondition_changed')
  assert.equal(setupDrift.patchClosed, false)
  assert.equal(setupDrift.patchBrokeHopId, null)
  assert.equal(setupDrift.brokeCausalEdge, null)
  assert.equal(setupDrift.brokeReason, null)
  assert.match(setupDrift.summary, /precondition changed/i)
  assert.equal(verifyCompositePatchRetestProofIntegrity(setupDrift), true)

  // Hop-level precondition drift on Hop 2 (route/schema refactored).
  const baseRunner = makeUnpatchedRunner()
  const hopDrift = await retestCompositeChainPatch({
    receipt,
    runner: {
      replayHop(ctx) {
        if (ctx.hop.hopId === 'hop-2') {
          return {
            outcome: 'precondition_changed',
            reason: 'GraphQL input type ReportRenderInput renamed; setup request cannot serialize',
          }
        }
        return baseRunner.replayHop(ctx)
      },
    },
    verifyOptions: { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY },
  })
  assert.equal(hopDrift.verdict, 'precondition_changed')
  assert.equal(hopDrift.patchClosed, false)
  assert.equal(hopDrift.patchBrokeHopId, null)
  assert.equal(toPortablePatchRetestProof(hopDrift).verdict, 'inconclusive')
  assert.equal(toPortablePatchRetestProof(hopDrift).compositeVerdict, 'precondition_changed')
})

// ============================================================================
// 6. Secret Redaction & OSS M4 Closure Gate Grading (>= 80%)
// ============================================================================

test('CompositePatchRetestProof redacts secrets and grades OSS M4 >= 80% closure honestly', async () => {
  const receipt = buildFourHopReceipt()
  const secretVal = 'tok_live_secret_value_never_leak_999'
  const baseRunner = makeUnpatchedRunner()

  const fixedProof = await retestCompositeChainPatch({
    receipt,
    runner: {
      replayHop(ctx) {
        if (ctx.hop.hopId === 'hop-3') {
          return {
            entries: [
              signedEntry('ex-3', makeStep({ id: 'ex-3', arm: 'probe', method: 'GET', status: 403, pathAndQuery: `/internal/jobs/${CORR_ID}/log` }), {
                timestampMs: 3000,
                actorPersona: 'member_a',
              }),
            ],
            reason: `Blocked request carrying ${secretVal} with HTTP 403`,
          }
        }
        return baseRunner.replayHop(ctx)
      },
    },
    verifyOptions: { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY },
    secrets: [{ placeholder: '[redacted:test_bearer]', value: secretVal }],
  })

  assert.equal(fixedProof.verdict, 'fixed')
  assert.equal(fixedProof.summary.includes(secretVal), false, 'Secret must be redacted from summary')
  assert.equal((fixedProof.brokeReason ?? '').includes(secretVal), false, 'Secret must be redacted from brokeReason')
  assert.equal(
    fixedProof.hopResults.some(h => (h.reason ?? '').includes(secretVal)),
    false,
    'Secret must be redacted from hopResults',
  )
  assert.equal(verifyCompositePatchRetestProofIntegrity(fixedProof), true)

  const vulnReceipt = {
    ...receipt,
    hops: receipt.hops.map(h => h.hopId === 'hop-4' ? { ...h, exchangeIds: ['ex-ctrl-4', 'ex-4'] } : h),
    terminalImpact: {
      ...receipt.terminalImpact,
      summary: 'Unauthorized settlement transfer executed via forged derived signature',
      terminalExchangeId: 'ex-4',
      preChainControlExchangeIds: ['ex-ctrl-4'],
      oracleInput: {
        tamperedSignatureControl: 'ex-ctrl-4',
        sourceValidIssuance: 'ex-3',
        replayedAcceptance: 'ex-4',
      },
    },
  }
  const vulnBaseRunner = makeUnpatchedRunner()
  const vulnProof = await retestCompositeChainPatch({
    receipt: vulnReceipt,
    runner: {
      replayHop(ctx) {
        const res = vulnBaseRunner.replayHop(ctx)
        if (ctx.hop.hopId === 'hop-4' && !('then' in res)) {
          return {
            ...res,
            entries: [
              signedEntry('ex-ctrl-4', makeStep({
                id: 'ex-ctrl-4',
                arm: 'control',
                method: 'POST',
                status: 403,
                pathAndQuery: '/api/v1/settlements/execute',
                requestHeaders: { 'x-signature': 'tampered-settlement-sig-deadbeef' },
                json: { error: 'forbidden' },
              }), {
                timestampMs: 900,
                actorPersona: 'member_a',
              }),
              signedEntry('ex-4', makeStep({
                id: 'ex-4',
                arm: 'probe',
                method: 'POST',
                status: 200,
                pathAndQuery: '/api/v1/settlements/execute',
                json: { tenantId: 'org-b', transferred: true, amount: 5000 },
              }), {
                timestampMs: 4000,
                actorPersona: 'member_a',
                consumedCapabilities: [CAP_HOP3],
                cryptoAttestations: [{
                  derivedFromCapabilityId: CAP_HOP3,
                  derivedCapabilityId: CAP_HOP4_DERIVED,
                  alg: 'hmac-sha256',
                  artifactDigest: sha256Hex('settlement-payload-v1'),
                  timestampMs: 3500,
                }],
              }),
            ],
          }
        }
        return res
      },
    },
    verifyOptions: { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY },
  })
  const inconclusiveProof = await retestCompositeChainPatch({
    receipt,
    runner: {
      preparePreconditions: () => ({ status: 'transport_error', reason: '503 upstream down', httpStatus: 503 }),
      replayHop: () => { throw new Error('unreachable') },
    },
  })

  // 4 fixed + 1 still_vulnerable = 80% -> passes M4 gate
  const passGate = summarizeCompositePatchClosure([fixedProof, fixedProof, fixedProof, fixedProof, vulnProof])
  assert.equal(passGate.total, 5)
  assert.equal(passGate.fixed, 4)
  assert.equal(passGate.stillVulnerable, 1)
  assert.equal(passGate.closureRate, 0.8)
  assert.equal(passGate.meetsM4ClosureGate, true)

  // 3 fixed + 1 inconclusive + 1 still_vulnerable = 60% -> fails M4 gate (inconclusive never inflates closure!)
  const failGate = summarizeCompositePatchClosure([fixedProof, fixedProof, fixedProof, inconclusiveProof, vulnProof])
  assert.equal(failGate.total, 5)
  assert.equal(failGate.fixed, 3)
  assert.equal(failGate.inconclusive, 1)
  assert.equal(failGate.closureRate, 0.6)
  assert.equal(failGate.meetsM4ClosureGate, false)
})

// ============================================================================
// 7. State-Transition Binding & Rate-Limit / Cyclic DAG Fail-Closed
// ============================================================================

test('state_transition_binding patched at Hop 3 -> fixed at hop-3 with exact edge kind; 429 & cyclic DAG -> inconclusive', async () => {
  const entityId = 'draft-order-77'
  const stReceipt: CompositeProofReceipt = {
    chainId: 'chain-state-transition-01',
    terminalVulnClass: 'business_logic',
    hops: [
      {
        hopId: 'hop-1',
        surface: 'http',
        target: { origin: ORIGIN_API, method: 'POST', pathAndQuery: '/api/v1/drafts' },
        exchangeIds: ['st-1'],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Create draft order',
        producedCapabilities: [],
        consumedCapabilities: [],
        entityId,
      },
      {
        hopId: 'hop-2',
        surface: 'http',
        target: { origin: ORIGIN_API, method: 'PATCH', pathAndQuery: `/api/v1/drafts/${entityId}` },
        exchangeIds: ['st-2'],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Benign draft edit',
        producedCapabilities: [],
        consumedCapabilities: [],
        entityId,
      },
      {
        hopId: 'hop-3',
        surface: 'http',
        target: { origin: ORIGIN_API, method: 'POST', pathAndQuery: `/api/v1/drafts/${entityId}/approve` },
        exchangeIds: ['st-3'],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Self-approve mutated draft',
        producedCapabilities: [],
        consumedCapabilities: [],
        entityId,
      },
    ],
    causalEdges: [
      {
        kind: 'state_transition_binding',
        fromHopId: 'hop-1',
        toHopId: 'hop-2',
        entityId,
        ablationExchangeIds: ['ab-1-2'],
      },
      {
        kind: 'state_transition_binding',
        fromHopId: 'hop-2',
        toHopId: 'hop-3',
        entityId,
        ablationExchangeIds: ['ab-2-3'],
      },
    ],
    terminalImpact: {
      terminalHopId: 'hop-3',
      claimedImpact: 'Unauthorized self-approval of draft order',
      preChainControlExchangeIds: [],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }

  // Patched at hop-3: maker-checker guard now denies self-approval with HTTP 403.
  const fixedState = await retestCompositeChainPatch({
    receipt: stReceipt,
    runner: {
      replayHop(ctx) {
        if (ctx.hop.hopId === 'hop-1') {
          return {
            entries: [
              signedEntry('st-1', makeStep({ id: 'st-1', arm: 'probe', method: 'POST', status: 201, pathAndQuery: '/api/v1/drafts', json: { id: entityId } }), {
                timestampMs: 1000,
                entityId,
              }),
            ],
          }
        }
        if (ctx.hop.hopId === 'hop-2') {
          return {
            entries: [
              signedEntry('st-2', makeStep({ id: 'st-2', arm: 'probe', method: 'PATCH', status: 200, pathAndQuery: `/api/v1/drafts/${entityId}`, json: { id: entityId } }), {
                timestampMs: 2000,
                entityId,
              }),
              signedEntry('ab-1-2', makeStep({ id: 'ab-1-2', arm: 'control', method: 'PATCH', status: 404, pathAndQuery: `/api/v1/drafts/${entityId}` }), {
                timestampMs: 1500,
                entityId,
                cleanSession: true,
                replayAttempt: 'ablation_control',
              }),
            ],
          }
        }
        return {
          entries: [
            signedEntry('st-3', makeStep({ id: 'st-3', arm: 'probe', method: 'POST', status: 403, pathAndQuery: `/api/v1/drafts/${entityId}/approve`, json: { error: 'creator_cannot_approve' } }), {
              timestampMs: 3000,
              entityId,
            }),
          ],
          reason: 'Maker-checker invariant preserved: creator cannot self-approve (HTTP 403)',
        }
      },
    },
    verifyOptions: { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY },
  })

  assert.equal(fixedState.verdict, 'fixed')
  assert.equal(fixedState.patchBrokeHopId, 'hop-3')
  assert.deepEqual(fixedState.benignPrefixHops, ['hop-1', 'hop-2'])
  assert.equal(fixedState.brokeCausalEdge?.kind, 'state_transition_binding')
  assert.equal(fixedState.brokeCausalEdge?.fromHopId, 'hop-2')
  assert.equal(fixedState.brokeCausalEdge?.toHopId, 'hop-3')

  // HTTP 429 rate-limit during replay MUST fail closed to 'inconclusive'.
  const rateLimited = await retestCompositeChainPatch({
    receipt: stReceipt,
    runner: {
      replayHop: ctx => ({
        entries: [
          signedEntry(`rl-${ctx.hop.hopId}`, makeStep({ id: `rl-${ctx.hop.hopId}`, arm: 'probe', method: 'POST', status: 429, pathAndQuery: '/api/v1/drafts' }), {
            timestampMs: 1000,
          }),
        ],
      }),
    },
    verifyOptions: { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY },
  })
  assert.equal(rateLimited.verdict, 'inconclusive')
  assert.equal(rateLimited.patchClosed, false)
  assert.equal(rateLimited.patchBrokeHopId, null)

  // Cyclic DAG MUST fail closed to 'inconclusive' without executing hops.
  const cyclicReceipt: CompositeProofReceipt = {
    ...stReceipt,
    causalEdges: [
      ...stReceipt.causalEdges,
      { kind: 'value_binding', fromHopId: 'hop-3', toHopId: 'hop-1', capabilityHandle: CAP_HOP1 },
    ],
  }
  const cyclicRes = await retestCompositeChainPatch({
    receipt: cyclicReceipt,
    runner: { replayHop: () => { throw new Error('must not run on cyclic DAG') } },
  })
  assert.equal(cyclicRes.verdict, 'inconclusive')
  assert.equal(cyclicRes.patchClosed, false)
  assert.match(cyclicRes.summary, /cycle/i)
})
