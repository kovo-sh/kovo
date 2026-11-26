/**
 * Systemic Stream A (sys-host-autodag) focused regression suite.
 *
 * Covers the host-derived Auto-DAG & dual-tenant provenance salvage (commit 30e4978) without
 * weakening any fail-closed security invariant:
 *  1. Host-derived Auto-DAG inference (`composite-autodag.ts`): omitted/partial kernel-observed
 *     capability edges are inferred from `HostFactLog` `emittedCapabilities` ->
 *     `consumedCapabilities` and `cryptoAttestations.derivedFromCapabilityId`, while fabricated
 *     or unlinked chains, reversed timestamps, control/cleanup/terminal-setup arms, duplicate
 *     hopIds, 1-hop receipts, and cyclic edge pairs remain strictly rejected.
 *  2. `dual_tenant_abac` persona provenance: a multi-tenant persona (admin in tenant A +
 *     low-privilege in tenant B) is an allowed attacker against tenant B, while the same persona
 *     attacking its own admin tenant and privileged victim-tenant personas stay forbidden.
 *  3. Dynamic-ID normalization in `matchesCtrlTarget` (denied controls on sibling dynamic
 *     resource IDs of the same route confirm; static-noun drift does not) and the
 *     state-reading post-chain readback exemption from attacker-provenance scanning.
 *  4. Failed `prove_*` RPC calls never poison `ctx.claims` — they surface only through the
 *     `_lastFailedClaims` fallback of `effectiveClaims()`, and a later success clears it.
 *  5. First-class `host_evaluated_expression` evaluation in `verify-claims.ts` (host-minted
 *     challenge oracle, control leakage / reflection / non-varying operand guards).
 *  6. LOC ceilings, zero dynamic `new RegExp()`, type-only (non-circular) Auto-DAG imports,
 *     and zero benchmark-app contamination literals.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import {
  augmentCompositeReceiptWithAutoDag,
  isDynamicResourceIdSegment,
  matchesNormalizedCtrlPath,
} from '../src/server/composite-autodag.ts'
import {
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { HostFactLog, resolveCanonicalArm } from '../src/server/host-fact-log.ts'
import { buildCompositeVerifyOptionsFromGrant } from '../src/server/agent-script-proof.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { defaultHostMintedOracle } from '../src/server/proof-receipt.ts'
import { isPrivilegedActorOrRole } from '../src/server/v8-oracle-hydrate.ts'
import {
  causalFingerprints,
  describeMissingEvidence,
  evaluateClaim,
  evaluateClaims,
  TranscriptStore,
} from '../src/server/verify-claims.ts'
import {
  VERIFY_NONCE_ENV,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import { VerifyContext } from '../worker/kovo_verify/kovo_verify.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'sys-host-autodag-test-signing-key-24681357'

function makeStep(partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: partial.actor ?? {
      handle: 'member_a',
      role: 'member',
      tenant: 'org_a',
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
): HostTranscriptEntry {
  const base: HostTranscriptEntry = {
    exchangeId,
    step,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
  return { ...base, hostSignature: signHostRecord(base, SIGNING_KEY) }
}

/** Minimal valid `CompositeProofReceipt` skeleton (post-zod-defaults shape). */
function makeReceipt(partial: {
  chainId: string
  terminalVulnClass: string
  hops: Array<{ hopId: string; method: string; pathAndQuery: string; exchangeIds: string[]; claimedDelta: string; producedCapabilities?: string[]; consumedCapabilities?: string[] }>
  causalEdges: CompositeProofReceipt['causalEdges']
  terminalHopId: string
  terminalExchangeId?: string
  preChainControlExchangeIds?: string[]
  postChainReadbackExchangeIds?: string[]
  summary: string
}): CompositeProofReceipt {
  return {
    chainId: partial.chainId,
    terminalVulnClass: partial.terminalVulnClass,
    hops: partial.hops.map(h => ({
      hopId: h.hopId,
      surface: 'http' as const,
      target: { origin: ORIGIN, method: h.method, pathAndQuery: h.pathAndQuery },
      exchangeIds: h.exchangeIds,
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: h.claimedDelta,
      producedCapabilities: h.producedCapabilities ?? [],
      consumedCapabilities: h.consumedCapabilities ?? [],
    })),
    causalEdges: partial.causalEdges,
    terminalImpact: {
      terminalHopId: partial.terminalHopId,
      claimedImpact: partial.summary,
      summary: partial.summary,
      ...(partial.terminalExchangeId !== undefined ? { terminalExchangeId: partial.terminalExchangeId } : {}),
      preChainControlExchangeIds: partial.preChainControlExchangeIds ?? [],
      postChainReadbackExchangeIds: partial.postChainReadbackExchangeIds ?? [],
    },
    replayMode: 'fresh_clean_replay' as const,
  }
}

// ============================================================================
// 1. Host-Derived Auto-DAG Inference (composite-autodag.ts)
// ============================================================================

test('Auto-DAG: host-observed capability flows infer omitted and partial value/crypto edges deterministically', () => {
  const cap = 'cap:hop_1:export_tok'
  const cap2 = 'cap:hop_2:download_tok'
  const keyCap = 'cap:hop_1:sign_key'
  const sigDigest = sha256Hex('autodag-derived-hmac-sig-01')

  // (a) Omitted edge: host fact log observes hop_1 emitting `cap`, hop_2 consuming it.
  const h1Setup = signedEntry('adag-h1', makeStep({
    id: 'adag-h1', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/directory/items',
    json: { token: 'opaque-export-token-123' },
  }), { timestampMs: 1000, emittedCapabilities: [cap] })
  const h2Probe = signedEntry('adag-h2', makeStep({
    id: 'adag-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/foreign-doc',
    json: { tenantId: 'org_b', rows: [{ id: 'row-1', total: 5000 }] },
  }), { timestampMs: 1200, consumedCapabilities: [cap] })
  const omittedReceipt = makeReceipt({
    chainId: 'sys-adag-omitted', terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/directory/items', exchangeIds: ['adag-h1'], claimedDelta: 'Setup hop fetched export capability', producedCapabilities: [cap] },
      { hopId: 'hop_2', method: 'GET', pathAndQuery: '/api/v1/exports/foreign-doc', exchangeIds: ['adag-h2'], claimedDelta: 'Probe hop read foreign tenant export', consumedCapabilities: [cap] },
    ],
    causalEdges: [],
    terminalHopId: 'hop_2', terminalExchangeId: 'adag-h2',
    summary: 'Unauthorized cross-tenant export read using Hop 1 capability.',
  })
  const logA = HostFactLog.fromTranscript({ entries: [h1Setup, h2Probe] })
  const outA = augmentCompositeReceiptWithAutoDag(omittedReceipt, logA)
  assert.equal(outA.inferredEdges.length, 1, `expected exactly one inferred value_binding, got ${JSON.stringify(outA.inferredEdges)}`)
  const edgeA = outA.inferredEdges[0]!
  if (edgeA.kind !== 'value_binding') throw new Error(`expected a value_binding edge, got ${edgeA.kind}`)
  assert.equal(edgeA.fromHopId, 'hop_1')
  assert.equal(edgeA.toHopId, 'hop_2')
  assert.equal(edgeA.capabilityHandle, cap)
  assert.equal(edgeA.sourceExchangeId, 'adag-h1')
  assert.equal(edgeA.targetExchangeId, 'adag-h2')
  assert.equal(outA.receipt.causalEdges.length, 1)
  assert.equal(outA.receipt.causalEdges[0]!.kind, 'value_binding')
  // The original receipt object is never mutated.
  assert.equal(omittedReceipt.causalEdges.length, 0)

  // (b) Partial edges: hop_1 -> hop_2 is explicit; the missing hop_2 -> hop_3 leg is inferred.
  const h2Mid = signedEntry('adag-h2b', makeStep({
    id: 'adag-h2b', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/foreign-doc/meta',
    json: { downloadToken: 'dl-tok-1' },
  }), { timestampMs: 1200, emittedCapabilities: [cap2] })
  const h3Probe = signedEntry('adag-h3', makeStep({
    id: 'adag-h3', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/foreign-doc/download',
    json: { tenantId: 'org_c', records: [{ id: 'r-1' }] },
  }), { timestampMs: 1400, consumedCapabilities: [cap2] })
  const partialReceipt = makeReceipt({
    chainId: 'sys-adag-partial', terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/directory/items', exchangeIds: ['adag-h1'], claimedDelta: 'Setup hop fetched export capability', producedCapabilities: [cap] },
      { hopId: 'hop_2', method: 'GET', pathAndQuery: '/api/v1/exports/foreign-doc/meta', exchangeIds: ['adag-h2b'], claimedDelta: 'Resolved download token', consumedCapabilities: [cap], producedCapabilities: [cap2] },
      { hopId: 'hop_3', method: 'GET', pathAndQuery: '/api/v1/exports/foreign-doc/download', exchangeIds: ['adag-h3'], claimedDelta: 'Downloaded foreign tenant records', consumedCapabilities: [cap2] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalHopId: 'hop_3', terminalExchangeId: 'adag-h3',
    summary: 'Unauthorized cross-tenant export download via resolved download token.',
  })
  const outB = augmentCompositeReceiptWithAutoDag(partialReceipt, HostFactLog.fromTranscript({ entries: [h1Setup, h2Mid, h3Probe] }))
  assert.equal(outB.inferredEdges.length, 1, `expected only the missing hop_2->hop_3 leg, got ${JSON.stringify(outB.inferredEdges)}`)
  const edgeB = outB.inferredEdges[0]!
  if (edgeB.kind !== 'value_binding') throw new Error(`expected a value_binding edge, got ${edgeB.kind}`)
  assert.equal(edgeB.fromHopId, 'hop_2')
  assert.equal(edgeB.toHopId, 'hop_3')
  assert.equal(edgeB.capabilityHandle, cap2)

  // (c) derivedFromCapabilityId -> derived_crypto_binding inference.
  const k1 = signedEntry('adag-k1', makeStep({
    id: 'adag-k1', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/trace',
    json: { signingSalt: 'secret-salt-value-123' },
  }), { timestampMs: 1000, emittedCapabilities: [keyCap] })
  const k2 = signedEntry('adag-k2', makeStep({
    id: 'adag-k2', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/settlement/webhook',
    json: { tenantId: 'org_b', settled: true, amount: 5000 },
  }), {
    timestampMs: 1200,
    cryptoAttestations: [{ derivedFromCapabilityId: keyCap, alg: 'sha256', artifactDigest: sigDigest, timestampMs: 1100 }],
  })
  const cryptoReceipt = makeReceipt({
    chainId: 'sys-adag-crypto', terminalVulnClass: 'forged_settlement',
    hops: [
      { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/trace', exchangeIds: ['adag-k1'], claimedDelta: 'Extracted signing salt', producedCapabilities: [keyCap] },
      { hopId: 'hop_2', method: 'POST', pathAndQuery: '/api/v1/settlement/webhook', exchangeIds: ['adag-k2'], claimedDelta: 'Signed forged settlement webhook' },
    ],
    causalEdges: [],
    terminalHopId: 'hop_2', terminalExchangeId: 'adag-k2',
    summary: 'Forged settlement webhook accepted using extracted signing salt.',
  })
  const outC = augmentCompositeReceiptWithAutoDag(cryptoReceipt, HostFactLog.fromTranscript({ entries: [k1, k2] }))
  assert.equal(outC.inferredEdges.length, 1, `expected one inferred derived_crypto_binding, got ${JSON.stringify(outC.inferredEdges)}`)
  const edgeC = outC.inferredEdges[0]!
  if (edgeC.kind !== 'derived_crypto_binding') throw new Error(`expected a derived_crypto_binding edge, got ${edgeC.kind}`)
  assert.equal(edgeC.fromHopId, 'hop_1')
  assert.equal(edgeC.toHopId, 'hop_2')
  assert.equal(edgeC.sourceCapabilityId, keyCap)
})

test('Auto-DAG: fabricated/unlinked chains, reversed timestamps, non-exec arms, 1-hop, duplicate hopIds, and cyclic pairs are never inferred', () => {
  const cap = 'cap:hop_1:sec_tok'

  const mkPair = (opts: {
    h1Arm?: ImpactStep['arm']
    h1Ts: number
    h1Emits?: string[]
    h2Arm?: ImpactStep['arm']
    h2Ts: number
    h2Consumes?: string[]
  }) => ({
    h1: signedEntry('ad-rj-h1', makeStep({
      id: 'ad-rj-h1', arm: opts.h1Arm ?? 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/source',
      json: { token: 'tok-abc' },
    }), { timestampMs: opts.h1Ts, ...(opts.h1Emits ? { emittedCapabilities: opts.h1Emits } : {}) }),
    h2: signedEntry('ad-rj-h2', makeStep({
      id: 'ad-rj-h2', arm: opts.h2Arm ?? 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/secret/doc',
      json: { tenantId: 'org_b', secret: 'classified' },
    }), { timestampMs: opts.h2Ts, ...(opts.h2Consumes ? { consumedCapabilities: opts.h2Consumes } : {}) }),
  })

  const mkTwoHopReceipt = (causalEdges: CompositeProofReceipt['causalEdges']): CompositeProofReceipt => makeReceipt({
    chainId: 'sys-adag-reject', terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/source', exchangeIds: ['ad-rj-h1'], claimedDelta: 'Hop 1' },
      { hopId: 'hop_2', method: 'GET', pathAndQuery: '/api/v1/secret/doc', exchangeIds: ['ad-rj-h2'], claimedDelta: 'Hop 2' },
    ],
    causalEdges,
    terminalHopId: 'hop_2', terminalExchangeId: 'ad-rj-h2',
    summary: 'Unauthorized cross-tenant secret document read.',
  })

  // (a) Fabricated / unlinked: hop_2 consumes a capability no kernel exchange ever emitted.
  const unlinked = mkPair({ h1Ts: 1000, h1Emits: [], h2Ts: 1200, h2Consumes: [cap] })
  const unlinkedOut = augmentCompositeReceiptWithAutoDag(
    mkTwoHopReceipt([]),
    HostFactLog.fromTranscript({ entries: [unlinked.h1, unlinked.h2] }),
  )
  assert.equal(unlinkedOut.inferredEdges.length, 0)
  assert.strictEqual(unlinkedOut.receipt.causalEdges.length, 0)

  // (b) Reversed timestamps: emission strictly after consumption is chronologically impossible.
  const reversed = mkPair({ h1Ts: 1200, h1Emits: [cap], h2Ts: 1000, h2Consumes: [cap] })
  const reversedOut = augmentCompositeReceiptWithAutoDag(
    mkTwoHopReceipt([]),
    HostFactLog.fromTranscript({ entries: [reversed.h1, reversed.h2] }),
  )
  assert.equal(reversedOut.inferredEdges.length, 0, 'reversed-timestamp capability flow must never yield an edge')

  // (c) Non-execution arms never seed emissions: control/cleanup emitters are not attacker-capable.
  for (const badArm of ['control', 'cleanup'] as const) {
    const nonExec = mkPair({ h1Arm: badArm, h1Ts: 1000, h1Emits: [cap], h2Ts: 1200, h2Consumes: [cap] })
    const nonExecOut = augmentCompositeReceiptWithAutoDag(
      mkTwoHopReceipt([]),
      HostFactLog.fromTranscript({ entries: [nonExec.h1, nonExec.h2] }),
    )
    assert.equal(nonExecOut.inferredEdges.length, 0, `arm='${badArm}' emitter must not seed Auto-DAG edges`)
  }

  // (d) arm='setup' on the TERMINAL hop is not an execution arm (H-11) -> no inference.
  const termSetup = mkPair({ h1Ts: 1000, h1Emits: [cap], h2Arm: 'setup', h2Ts: 1200, h2Consumes: [cap] })
  const termSetupOut = augmentCompositeReceiptWithAutoDag(
    mkTwoHopReceipt([]),
    HostFactLog.fromTranscript({ entries: [termSetup.h1, termSetup.h2] }),
  )
  assert.equal(termSetupOut.inferredEdges.length, 0, 'terminal setup-arm consumption must never be wired by Auto-DAG')

  // (e) 1-hop receipts and duplicate hopIds are left untouched.
  const oneHop = makeReceipt({
    chainId: 'sys-adag-1hop', terminalVulnClass: 'bola',
    hops: [{ hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/secret/doc', exchangeIds: ['ad-rj-h2'], claimedDelta: 'Single hop' }],
    causalEdges: [],
    terminalHopId: 'hop_1', terminalExchangeId: 'ad-rj-h2',
    summary: 'Attempted single-hop confirmation.',
  })
  const oneHopOut = augmentCompositeReceiptWithAutoDag(oneHop, HostFactLog.fromTranscript({ entries: [mkPair({ h1Ts: 1000, h1Emits: [cap], h2Ts: 1200, h2Consumes: [cap] }).h2] }))
  assert.strictEqual(oneHopOut.receipt, oneHop)
  assert.equal(oneHopOut.inferredEdges.length, 0)

  const dupHop = makeReceipt({
    chainId: 'sys-adag-dup', terminalVulnClass: 'bola',
    hops: [
      { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/source', exchangeIds: ['ad-rj-h1'], claimedDelta: 'Hop 1' },
      { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/secret/doc', exchangeIds: ['ad-rj-h2'], claimedDelta: 'Hop 2' },
    ],
    causalEdges: [],
    terminalHopId: 'hop_1', terminalExchangeId: 'ad-rj-h2',
    summary: 'Attempted duplicate-hopId confirmation.',
  })
  const pair = mkPair({ h1Ts: 1000, h1Emits: [cap], h2Ts: 1200, h2Consumes: [cap] })
  const dupOut = augmentCompositeReceiptWithAutoDag(dupHop, HostFactLog.fromTranscript({ entries: [pair.h1, pair.h2] }))
  assert.strictEqual(dupOut.receipt, dupHop)
  assert.equal(dupOut.inferredEdges.length, 0)

  // (f) Cyclic pair guard: an explicit hop_2 -> hop_1 edge blocks inferring the reverse leg.
  const cyclicReceipt = makeReceipt({
    chainId: 'sys-adag-cycle', terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/source', exchangeIds: ['ad-rj-h1'], claimedDelta: 'Hop 1', producedCapabilities: [cap] },
      { hopId: 'hop_2', method: 'GET', pathAndQuery: '/api/v1/secret/doc', exchangeIds: ['ad-rj-h2'], claimedDelta: 'Hop 2', consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_1', capabilityHandle: 'cap:hop_2:backflow' }],
    terminalHopId: 'hop_2', terminalExchangeId: 'ad-rj-h2',
    summary: 'Attempted cycle-closing Auto-DAG inference.',
  })
  const cyclicOut = augmentCompositeReceiptWithAutoDag(cyclicReceipt, HostFactLog.fromTranscript({ entries: [pair.h1, pair.h2] }))
  assert.equal(cyclicOut.inferredEdges.length, 0, 'Auto-DAG must never close a causal cycle')

  // (g) An explicit edge is never re-inferred (no duplicate edges, no rewriting).
  const explicitReceipt = makeReceipt({
    chainId: 'sys-adag-explicit', terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/source', exchangeIds: ['ad-rj-h1'], claimedDelta: 'Hop 1', producedCapabilities: [cap] },
      { hopId: 'hop_2', method: 'GET', pathAndQuery: '/api/v1/secret/doc', exchangeIds: ['ad-rj-h2'], claimedDelta: 'Hop 2', consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalHopId: 'hop_2', terminalExchangeId: 'ad-rj-h2',
    summary: 'Explicitly bound cross-tenant secret document read.',
  })
  const explicitOut = augmentCompositeReceiptWithAutoDag(explicitReceipt, HostFactLog.fromTranscript({ entries: [pair.h1, pair.h2] }))
  assert.equal(explicitOut.inferredEdges.length, 0)
  assert.equal(explicitOut.receipt.causalEdges.length, 1)
})

test('Auto-DAG end-to-end: verifyCompositeReceipt confirms host-derived edges (autoInferredEdgeCount) and rejects unlinked chains fail-closed', () => {
  const cap = 'cap:hop_1:export_tok'
  const ctrl = signedEntry('ad-e2e-ctrl', makeStep({
    id: 'ad-e2e-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/exports/foreign-doc',
    json: { error: 'forbidden' },
  }), { timestampMs: 900 })
  const h1Setup = signedEntry('ad-e2e-h1', makeStep({
    id: 'ad-e2e-h1', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/directory/items',
    json: { token: 'opaque-export-token-123' },
  }), { timestampMs: 1000, emittedCapabilities: [cap] })
  const h2Probe = signedEntry('ad-e2e-h2', makeStep({
    id: 'ad-e2e-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/foreign-doc',
    json: { tenantId: 'org_b', rows: [{ id: 'row-1', total: 5000 }] },
  }), { timestampMs: 1200, consumedCapabilities: [cap] })
  const transcript: HostSignedTranscript = { entries: [ctrl, h1Setup, h2Probe] }

  const buildReceipt = (): CompositeProofReceipt => makeReceipt({
    chainId: 'sys-adag-e2e', terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/directory/items', exchangeIds: ['ad-e2e-h1'], claimedDelta: 'Setup hop fetched export capability', producedCapabilities: [cap] },
      { hopId: 'hop_2', method: 'GET', pathAndQuery: '/api/v1/exports/foreign-doc', exchangeIds: ['ad-e2e-h2'], claimedDelta: 'Probe hop read foreign tenant export', consumedCapabilities: [cap] },
    ],
    causalEdges: [],
    terminalHopId: 'hop_2', terminalExchangeId: 'ad-e2e-h2',
    preChainControlExchangeIds: ['ad-e2e-ctrl'],
    summary: 'Unauthorized cross-tenant export read using Hop 1 capability.',
  })

  // (a) Omitted edges + genuine host-observed capability flow -> confirmed with inference count.
  const confirmed = verifyCompositeReceipt(buildReceipt(), transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(confirmed.confirmed, true, confirmed.reason)
  assert.equal(confirmed.verifiedEdges.length, 1)
  assert.equal(confirmed.verifiedEdges[0]!.kind, 'value_binding')
  assert.equal(confirmed.verifiedEdges[0]!.verified, true)
  assert.equal(confirmed.evidence?.autoInferredEdgeCount, 1)

  // (b) Unlinked chain: the host never observed the claimed capability -> fail closed at dag_topology.
  const h1NoEmit = signedEntry('ad-e2e-h1-bare', makeStep({
    id: 'ad-e2e-h1-bare', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/directory/items',
    json: { token: 'opaque-export-token-123' },
  }), { timestampMs: 1000 })
  const bareTranscript: HostSignedTranscript = { entries: [ctrl, h1NoEmit, h2Probe] }
  const bareReceipt = makeReceipt({
    chainId: 'sys-adag-unlinked', terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/directory/items', exchangeIds: ['ad-e2e-h1-bare'], claimedDelta: 'Setup hop fetched export capability', producedCapabilities: [cap] },
      { hopId: 'hop_2', method: 'GET', pathAndQuery: '/api/v1/exports/foreign-doc', exchangeIds: ['ad-e2e-h2'], claimedDelta: 'Probe hop read foreign tenant export', consumedCapabilities: [cap] },
    ],
    causalEdges: [],
    terminalHopId: 'hop_2', terminalExchangeId: 'ad-e2e-h2',
    preChainControlExchangeIds: ['ad-e2e-ctrl'],
    summary: 'Unauthorized cross-tenant export read using Hop 1 capability.',
  })
  const rejected = verifyCompositeReceipt(bareReceipt, bareTranscript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(rejected.confirmed, false)
  assert.equal(rejected.failedStage, 'dag_topology')
  assert.match(rejected.reason, /does not reach terminalHopId/)

  // (c) derivedFromCapabilityId end-to-end: omitted derived_crypto_binding is inferred and confirms.
  const keyCap = 'cap:hop_1:sign_key'
  const sigDigest = sha256Hex('autodag-e2e-derived-sig')
  const k1 = signedEntry('ad-e2e-k1', makeStep({
    id: 'ad-e2e-k1', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/trace',
    json: { signingSalt: 'secret-salt-value-123' },
  }), { timestampMs: 1000, emittedCapabilities: [keyCap] })
  const k2 = signedEntry('ad-e2e-k2', makeStep({
    id: 'ad-e2e-k2', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/settlement/webhook',
    json: { tenantId: 'org_b', settled: true, amount: 5000 },
  }), {
    timestampMs: 1200,
    cryptoAttestations: [{ derivedFromCapabilityId: keyCap, alg: 'sha256', artifactDigest: sigDigest, timestampMs: 1100 }],
  })
  const cryptoRes = verifyCompositeReceipt(makeReceipt({
    chainId: 'sys-adag-crypto-e2e', terminalVulnClass: 'forged_settlement',
    hops: [
      { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/trace', exchangeIds: ['ad-e2e-k1'], claimedDelta: 'Extracted signing salt', producedCapabilities: [keyCap] },
      { hopId: 'hop_2', method: 'POST', pathAndQuery: '/api/v1/settlement/webhook', exchangeIds: ['ad-e2e-k2'], claimedDelta: 'Signed forged settlement webhook' },
    ],
    causalEdges: [],
    terminalHopId: 'hop_2', terminalExchangeId: 'ad-e2e-k2',
    summary: 'Forged settlement webhook accepted using extracted signing salt.',
  }), { entries: [k1, k2] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(cryptoRes.confirmed, true, cryptoRes.reason)
  assert.equal(cryptoRes.evidence?.autoInferredEdgeCount, 1)
  assert.equal(cryptoRes.verifiedEdges[0]!.kind, 'derived_crypto_binding')
})

// ============================================================================
// 2. dual_tenant_abac Persona Provenance
// ============================================================================

test('dual_tenant_abac: multi-tenant admin-in-A / low-priv-in-B personas are allowed against tenant B; privileged personas stay forbidden', () => {
  // (a) Privilege classifier: tenant-aware allowance with a low-privilege foothold membership.
  assert.equal(isPrivilegedActorOrRole('member_ab', 'member', 'admin (org_a), member (org_b)', 'org_b'), false, 'low-priv tenant target must be allowed')
  assert.equal(isPrivilegedActorOrRole('member_ab', 'member', 'admin (org_a), member (org_b)', 'org_a'), true, 'own admin tenant target must stay forbidden')
  assert.equal(isPrivilegedActorOrRole('member_ab', 'member', 'admin (org_a), member (org_b)'), false, 'without a target tenant the dual-tenant persona is not blanket-forbidden')
  assert.equal(isPrivilegedActorOrRole('victim_admin_b', 'admin', 'admin (org_b)', 'org_b'), true, 'single-tenant victim admin is always forbidden')
  assert.equal(isPrivilegedActorOrRole('admin_only', 'admin', 'admin (org_a), admin (org_b)', 'org_b'), true, 'multi-tenant without any low-priv membership stays forbidden')
  assert.equal(isPrivilegedActorOrRole('owner_mix', 'member', 'owner (org_a), viewer (org_b)', 'org_b'), true, 'owner membership anywhere is forbidden')
  assert.equal(isPrivilegedActorOrRole('svc_root', 'member', 'platform superadmin, member (org_z)', 'org_z'), true, 'global privileged labels are forbidden')
  assert.equal(isPrivilegedActorOrRole('plain_member_b', 'member', 'member (org_b)', 'org_b'), false, 'ordinary low-privilege member stays allowed')

  // (b) Grant-derived composite verify options: dual-tenant personas route to attackerPersonas.
  const mkPersona = (handle: string, roleLabel: string): ResolvedPersona => ({
    id: `persona-${handle}`, handle, roleLabel, originAllowlist: [ORIGIN], authKind: 'header',
    headerName: 'X-User', secret: `secret-${handle}-01`, canaryMarkers: [],
  })
  const grant: Pick<Grant, 'personas'> = {
    personas: new Map<string, ResolvedPersona>([
      ['member_ab', mkPersona('member_ab', 'admin (org_a), member (org_b)')],
      ['plain_member_b', mkPersona('plain_member_b', 'member (org_b)')],
      ['org_admin_a', mkPersona('org_admin_a', 'admin (org_a)')],
      ['svc_root', mkPersona('svc_root', 'platform superadmin, member (org_z)')],
      ['owner_mix', mkPersona('owner_mix', 'owner (org_a), viewer (org_b)')],
    ]),
  }
  const options = buildCompositeVerifyOptionsFromGrant(grant)
  assert.ok(options, 'expected grant-derived composite verify options')
  assert.deepEqual([...(options?.attackerPersonas ?? [])].sort(), ['member_ab', 'plain_member_b'])
  assert.deepEqual([...(options?.forbiddenShortcutPersonas ?? [])].sort(), ['org_admin_a', 'owner_mix', 'svc_root'])

  // (c) Full composite verify: the dual-tenant persona attacks the VICTIM tenant (org_c) and confirms.
  const cap = 'cap:dual:hopper'
  const dualActor = { handle: 'member_ab', role: 'member' as const, tenant: 'org_b', auth: 'bearer' as const, sameSite: null }
  const dualCtrl = signedEntry('dual-ctrl', makeStep({
    id: 'dual-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/tenants/org_c/treasury',
    actor: dualActor, json: { error: 'forbidden' },
  }), { timestampMs: 900, actorPersona: 'member_ab', actorRoleLabel: 'admin (org_a), member (org_b)' })
  const dualH1 = signedEntry('dual-h1', makeStep({
    id: 'dual-h1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/self/permissions',
    actor: dualActor, json: { permission: 'member' },
  }), { timestampMs: 1000, actorPersona: 'member_ab', actorRoleLabel: 'admin (org_a), member (org_b)', emittedCapabilities: [cap] })
  const dualH2 = signedEntry('dual-h2', makeStep({
    id: 'dual-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/tenants/org_c/treasury',
    actor: dualActor, json: { tenantId: 'org_c', records: [{ id: 'tr-1', balanceCents: 990000 }] },
  }), { timestampMs: 1200, actorPersona: 'member_ab', actorRoleLabel: 'admin (org_a), member (org_b)', consumedCapabilities: [cap] })
  const dualTranscript: HostSignedTranscript = { entries: [dualCtrl, dualH1, dualH2] }
  const dualReceipt = makeReceipt({
    chainId: 'sys-adag-dual-tenant', terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/self/permissions', exchangeIds: ['dual-h1'], claimedDelta: 'Priming hop resolved the persona session', producedCapabilities: [cap] },
      { hopId: 'hop_2', method: 'GET', pathAndQuery: '/api/v1/tenants/org_c/treasury', exchangeIds: ['dual-h2'], claimedDelta: 'Victim-tenant treasury records exposed', consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalHopId: 'hop_2', terminalExchangeId: 'dual-h2',
    preChainControlExchangeIds: ['dual-ctrl'],
    summary: 'Cached admin membership from tenant A unlocked victim tenant C treasury data.',
  })
  const dualOk = verifyCompositeReceipt(dualReceipt, dualTranscript, { attackerPersonas: ['member_ab'], signingKey: SIGNING_KEY })
  assert.equal(dualOk.confirmed, true, dualOk.reason)
  assert.equal(dualOk.terminalOracleFamily, 'dual_tenant_abac')

  // (d) The SAME persona against its own admin tenant (org_a) MUST fail at attacker_provenance.
  const ownAdminCtrl = signedEntry('dual-own-ctrl', makeStep({
    id: 'dual-own-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/tenants/org_a/treasury',
    actor: dualActor, json: { error: 'forbidden' },
  }), { timestampMs: 900, actorPersona: 'member_ab', actorRoleLabel: 'admin (org_a), member (org_b)' })
  const ownAdminH2 = signedEntry('dual-own-h2', makeStep({
    id: 'dual-own-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/tenants/org_a/treasury',
    actor: dualActor, json: { tenantId: 'org_a', records: [{ id: 'tr-2', balanceCents: 880000 }] },
  }), { timestampMs: 1200, actorPersona: 'member_ab', actorRoleLabel: 'admin (org_a), member (org_b)', consumedCapabilities: [cap] })
  const ownAdminRes = verifyCompositeReceipt(makeReceipt({
    chainId: 'sys-adag-dual-own-admin', terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/self/permissions', exchangeIds: ['dual-h1'], claimedDelta: 'Priming hop resolved the persona session', producedCapabilities: [cap] },
      { hopId: 'hop_2', method: 'GET', pathAndQuery: '/api/v1/tenants/org_a/treasury', exchangeIds: ['dual-own-h2'], claimedDelta: 'Own admin tenant records exposed', consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalHopId: 'hop_2', terminalExchangeId: 'dual-own-h2',
    preChainControlExchangeIds: ['dual-own-ctrl'],
    summary: 'Attempted confirmation of own admin tenant treasury data.',
  }), { entries: [ownAdminCtrl, dualH1, ownAdminH2] }, { attackerPersonas: ['member_ab'], signingKey: SIGNING_KEY })
  assert.equal(ownAdminRes.confirmed, false)
  assert.equal(ownAdminRes.failedStage, 'attacker_provenance')
  assert.match(ownAdminRes.reason, /forbidden/)

  // (e) Privileged victim-tenant persona (admin of the victim tenant) MUST fail even when allowlisted.
  const victimActor = { handle: 'victim_admin_c', role: 'admin' as const, tenant: 'org_c', auth: 'bearer' as const, sameSite: null }
  const victimCtrl = signedEntry('victim-ctrl', makeStep({
    id: 'victim-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/tenants/org_c/treasury',
    actor: victimActor, json: { error: 'forbidden' },
  }), { timestampMs: 900, actorPersona: 'victim_admin_c', actorRoleLabel: 'admin (org_c)' })
  const victimH1 = signedEntry('victim-h1', makeStep({
    id: 'victim-h1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/self/permissions',
    actor: victimActor, json: { permission: 'admin' },
  }), { timestampMs: 1000, actorPersona: 'victim_admin_c', actorRoleLabel: 'admin (org_c)', emittedCapabilities: [cap] })
  const victimH2 = signedEntry('victim-h2', makeStep({
    id: 'victim-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/tenants/org_c/treasury',
    actor: victimActor, json: { tenantId: 'org_c', records: [{ id: 'tr-3', balanceCents: 770000 }] },
  }), { timestampMs: 1200, actorPersona: 'victim_admin_c', actorRoleLabel: 'admin (org_c)', consumedCapabilities: [cap] })
  const victimRes = verifyCompositeReceipt(makeReceipt({
    chainId: 'sys-adag-victim-tenant', terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/self/permissions', exchangeIds: ['victim-h1'], claimedDelta: 'Priming hop resolved the persona session', producedCapabilities: [cap] },
      { hopId: 'hop_2', method: 'GET', pathAndQuery: '/api/v1/tenants/org_c/treasury', exchangeIds: ['victim-h2'], claimedDelta: 'Victim tenant treasury records exposed', consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalHopId: 'hop_2', terminalExchangeId: 'victim-h2',
    preChainControlExchangeIds: ['victim-ctrl'],
    summary: 'Attempted confirmation using the victim tenant administrator persona.',
  }), { entries: [victimCtrl, victimH1, victimH2] }, { attackerPersonas: ['victim_admin_c'], signingKey: SIGNING_KEY })
  assert.equal(victimRes.confirmed, false)
  assert.equal(victimRes.failedStage, 'attacker_provenance')
  assert.match(victimRes.reason, /forbidden/)
})

// ============================================================================
// 3. Dynamic-ID Control Normalization & Readback Exemption
// ============================================================================

test('isDynamicResourceIdSegment and matchesNormalizedCtrlPath: canonical dynamic-ID slots, static anchors, and extension parity', () => {
  // Dynamic resource/job/export identifier segments.
  assert.equal(isDynamicResourceIdSegment('9f8e7d6c'), true, 'hex identifier is dynamic')
  assert.equal(isDynamicResourceIdSegment('0a1b2c3d-4e5f-6789-abcd-ef0123456789'), true, 'UUID is dynamic')
  assert.equal(isDynamicResourceIdSegment('12345'), true, 'numeric identifier is dynamic')
  assert.equal(isDynamicResourceIdSegment('job-88776655'), true, 'dashed identifier with digits is dynamic')
  assert.equal(isDynamicResourceIdSegment('cap:run_1:export_tok'), true, 'capability handle is dynamic')
  assert.equal(isDynamicResourceIdSegment('[redacted:cap:x]'), true, 'vault-scrubbed placeholder is dynamic')
  assert.equal(isDynamicResourceIdSegment('%39f8e7d6c'), true, 'percent-encoded identifier is dynamic')
  // Static route nouns and version prefixes never wildcard-match.
  assert.equal(isDynamicResourceIdSegment('users'), false)
  assert.equal(isDynamicResourceIdSegment('exports'), false)
  assert.equal(isDynamicResourceIdSegment('v2'), false, 'version prefixes are static')
  assert.equal(isDynamicResourceIdSegment('api'), false)
  assert.equal(isDynamicResourceIdSegment(''), false)

  // Normalized control-target matching.
  assert.equal(matchesNormalizedCtrlPath('/api/v1/exports/9f8e7d6c/download', '/api/v1/exports/3a2b1c0d/download'), true, 'sibling dynamic IDs on one route match')
  assert.equal(matchesNormalizedCtrlPath('/api/v1/exports/9f8e7d6c/download?sig=abc', '/api/v1/exports/3a2b1c0d/download?sig=def'), true, 'query strings are ignored')
  assert.equal(matchesNormalizedCtrlPath('/api/v2/files/report-9f8e7d6c.csv', '/api/v2/files/export-2a3b4c5d.csv'), true, 'extensions must be preserved across dynamic stems')
  assert.equal(matchesNormalizedCtrlPath('/api/v1/exports/9f8e7d6c/download', '/api/v1/reports/3a2b1c0d/download'), false, 'static route noun drift never matches')
  assert.equal(matchesNormalizedCtrlPath('/api/v1/exports/9f8e7d6c/download', '/api/v1/exports/3a2b1c0d'), false, 'segment count must agree')
  assert.equal(matchesNormalizedCtrlPath('/api/v2/files/report-9f8e7d6c.csv', '/api/v2/files/export-2a3b4c5d.pdf'), false, 'extension drift never matches')
  assert.equal(matchesNormalizedCtrlPath('/9f8e7d6c/a2b3c4d5', '/12345678/0a1b2c3d'), false, 'at least one identical static segment is required')
  assert.equal(matchesNormalizedCtrlPath('/api/v1/users/9f8e7d6c', '/api/v1/users/9f8e7d6c'), false, 'identical exact paths are handled by the exact-path branch, not the dynamic normalizer')
})

test('matchesCtrlTarget: denied controls on sibling dynamic resource IDs confirm; static-noun drift stays fail-closed', () => {
  const cap = 'cap:dyn:export_url'
  const ctrlEntry = (id: string, path: string): HostTranscriptEntry => signedEntry(id, makeStep({
    id, arm: 'control', method: 'GET', status: 403, pathAndQuery: path,
    json: { error: 'forbidden' },
  }), { timestampMs: 900 })

  const dynOkReceipt = (ctrlPath: string, ctrlId: string): { receipt: CompositeProofReceipt; transcript: HostSignedTranscript } => {
    const h1 = signedEntry('dyn-h1', makeStep({
      id: 'dyn-h1', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/directory/items',
      json: { token: 'opaque-export-token-456' },
    }), { timestampMs: 1000, emittedCapabilities: [cap] })
    const h2 = signedEntry('dyn-h2', makeStep({
      id: 'dyn-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/e77f0a21/download',
      json: { tenantId: 'org_b', rows: [{ id: 'row-9', total: 4242 }] },
    }), { timestampMs: 1200, consumedCapabilities: [cap] })
    return {
      receipt: makeReceipt({
        chainId: 'sys-adag-dyn-ctrl', terminalVulnClass: 'cross_tenant_read',
        hops: [
          { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/directory/items', exchangeIds: ['dyn-h1'], claimedDelta: 'Setup hop fetched export capability', producedCapabilities: [cap] },
          { hopId: 'hop_2', method: 'GET', pathAndQuery: '/api/v1/exports/e77f0a21/download', exchangeIds: ['dyn-h2'], claimedDelta: 'Probe hop downloaded foreign export', consumedCapabilities: [cap] },
        ],
        causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
        terminalHopId: 'hop_2', terminalExchangeId: 'dyn-h2',
        preChainControlExchangeIds: [ctrlId],
        summary: 'Unauthorized cross-tenant export download using Hop 1 capability.',
      }),
      transcript: { entries: [ctrlEntry(ctrlId, ctrlPath), h1, h2] },
    }
  }

  // (a) Control denied on a sibling dynamic ID of the same route -> normalized match confirms.
  const ok = dynOkReceipt('/api/v1/exports/0c9d8b7a/download', 'dyn-ctrl-sibling')
  const okRes = verifyCompositeReceipt(ok.receipt, ok.transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(okRes.confirmed, true, `sibling dynamic-ID control must confirm: ${okRes.reason}`)

  // (b) Control on a different static route noun -> no clean denied control -> fail closed.
  const drift = dynOkReceipt('/api/v1/shipments/0c9d8b7a/download', 'dyn-ctrl-drift')
  const driftRes = verifyCompositeReceipt(drift.receipt, drift.transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(driftRes.confirmed, false)
  assert.equal(driftRes.failedStage, 'terminal_impact')
  assert.ok(driftRes.missingEvidence?.includes('clean_denied_control_401_403_404'), `expected clean_denied_control evidence gap, got ${JSON.stringify(driftRes.missingEvidence)}`)
})

test('readback exemption: state-reading post-chain readbacks by target-tenant personas are exempt; mutating readbacks stay forbidden', () => {
  const cap = 'cap:rb:export_tok'
  const attacker = { handle: 'member_a', role: 'member' as const, tenant: 'org_a', auth: 'bearer' as const, sameSite: null }
  const victimAdmin = { handle: 'admin_b', role: 'admin' as const, tenant: 'org_b', auth: 'bearer' as const, sameSite: null }

  const ctrl = signedEntry('rb-ctrl', makeStep({
    id: 'rb-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/exports/foreign-doc',
    actor: attacker, json: { error: 'forbidden' },
  }), { timestampMs: 900 })
  const h1 = signedEntry('rb-h1', makeStep({
    id: 'rb-h1', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/directory/items',
    actor: attacker, json: { token: 'opaque-export-token-789' },
  }), { timestampMs: 1000, emittedCapabilities: [cap] })
  const h2 = signedEntry('rb-h2', makeStep({
    id: 'rb-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/foreign-doc',
    actor: attacker, json: { tenantId: 'org_b', rows: [{ id: 'row-2', total: 6400 }] },
  }), { timestampMs: 1200, consumedCapabilities: [cap] })
  // Target-tenant admin performs a state-READING readback (allowed arm for foreign personas).
  const rbGet = signedEntry('rb-get', makeStep({
    id: 'rb-get', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/foreign-doc/audit',
    actor: victimAdmin, json: { tenantId: 'org_b', auditedBy: 'admin_b', exposedRows: 1 },
  }), { timestampMs: 1400, actorPersona: 'admin_b', actorRoleLabel: 'admin (org_b)', evidenceRole: 'post_chain_readback' })
  // Target-tenant admin performs a MUTATING "readback" (not exempt: it is not a read arm).
  const rbMut = signedEntry('rb-mut', makeStep({
    id: 'rb-mut', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/exports/foreign-doc/annotate',
    actor: victimAdmin, json: { tenantId: 'org_b', annotated: true },
    requestJson: { note: 'attacker-annotated' },
  }), { timestampMs: 1400, actorPersona: 'admin_b', actorRoleLabel: 'admin (org_b)', evidenceRole: 'post_chain_readback' })

  const build = (readbackId: string): CompositeProofReceipt => makeReceipt({
    chainId: 'sys-adag-readback', terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', method: 'GET', pathAndQuery: '/api/v1/directory/items', exchangeIds: ['rb-h1'], claimedDelta: 'Setup hop fetched export capability', producedCapabilities: [cap] },
      { hopId: 'hop_2', method: 'GET', pathAndQuery: '/api/v1/exports/foreign-doc', exchangeIds: ['rb-h2'], claimedDelta: 'Probe hop read foreign tenant export', consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalHopId: 'hop_2', terminalExchangeId: 'rb-h2',
    preChainControlExchangeIds: ['rb-ctrl'],
    postChainReadbackExchangeIds: [readbackId],
    summary: 'Unauthorized cross-tenant export read confirmed by a target-tenant audit readback.',
  })

  // (a) State-reading readback by the target-tenant admin is exempt from provenance scanning.
  const okRes = verifyCompositeReceipt(build('rb-get'), { entries: [ctrl, h1, h2, rbGet] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(okRes.confirmed, true, okRes.reason)

  // (b) Mutating readback by a forbidden persona is NOT exempt and MUST fail at attacker_provenance.
  const mutRes = verifyCompositeReceipt(build('rb-mut'), { entries: [ctrl, h1, h2, rbMut] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(mutRes.confirmed, false)
  assert.equal(mutRes.failedStage, 'attacker_provenance')
  assert.match(mutRes.reason, /cited non-control exchange/)
  assert.match(mutRes.reason, /admin_b/)
})

// ============================================================================
// 4. Host-Fact-Log Canonical Arm & Capability Flow (Auto-DAG kernel input)
// ============================================================================

test('resolveCanonicalArm and HostFactLog.getExchangeCapabilityFlow expose frozen, canonical kernel facts', () => {
  assert.equal(resolveCanonicalArm('control'), 'control')
  assert.equal(resolveCanonicalArm('probe'), 'probe')
  assert.equal(resolveCanonicalArm('setup'), 'setup')
  assert.equal(resolveCanonicalArm('cleanup'), 'cleanup')
  assert.equal(resolveCanonicalArm(null), 'probe', 'unlabeled HTTP exchanges default to the probe arm')
  assert.equal(resolveCanonicalArm('surprise'), 'probe', 'unknown session roles default to the probe arm')
  assert.equal(resolveCanonicalArm(null, 'setup'), 'setup', 'explicit arms always win')

  const cap = 'cap:flow:export_tok'
  const keyCap = 'cap:flow:sign_key'
  const entry = signedEntry('flow-ex', makeStep({
    id: 'flow-ex', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/hydrate',
    json: { ok: true },
  }), {
    timestampMs: 1234,
    emittedCapabilities: [cap],
    consumedCapabilities: ['cap:flow:upstream', keyCap],
    cryptoAttestations: [{ derivedFromCapabilityId: keyCap, derivedCapabilityId: 'cap:flow:derived_sig', alg: 'sha256', artifactDigest: sha256Hex('flow-derived'), timestampMs: 1230 }],
  })
  const log = HostFactLog.fromTranscript({ entries: [entry] })
  const flow = log.getExchangeCapabilityFlow('flow-ex')
  assert.ok(flow, 'expected a capability flow record')
  assert.equal(flow!.arm, 'probe')
  assert.equal(flow!.timestampMs, 1234)
  assert.deepEqual([...flow!.emitted], [cap, 'cap:flow:derived_sig'], 'derived crypto capability ids count as emissions')
  assert.deepEqual([...flow!.consumed], ['cap:flow:upstream', keyCap])
  assert.equal(flow!.cryptoAttestations.length, 1)
  assert.ok(Object.isFrozen(flow!), 'capability flow records are frozen')
  assert.ok(Object.isFrozen(flow!.emitted), 'emission lists are frozen')
  assert.equal(log.getExchangeCapabilityFlow('missing-ex'), undefined)
})

// ============================================================================
// 5. First-Class host_evaluated_expression Evaluation (verify-claims.ts)
// ============================================================================

interface HeeStoreFixture {
  store: TranscriptStore
  controlId: string
  probeIds: string[]
}

function buildHeeStoreFixture(probeBodies: string[], probeStatus = 200): HeeStoreFixture {
  const store = new TranscriptStore()
  const mk = (role: 'control' | 'probe', body: string, status: number, rawRequestBody?: string) => {
    const request = {
      origin: ORIGIN,
      method: role === 'probe' ? 'POST' : 'GET',
      pathAndQuery: role === 'probe' ? '/api/v1/render' : '/api/v1/render?view=control',
      headers: {},
      bodyBytes: typeof rawRequestBody === 'string' ? Buffer.byteLength(rawRequestBody) : 0,
      bodySha256: sha256Hex(rawRequestBody ?? ''),
      sessionRole: role,
      personaHandle: role === 'probe' ? 'member_a' : 'viewer_a',
      nonce: `n-${role}-${Math.random().toString(36).slice(2, 8)}`,
    }
    return store.record({
      op: 'http' as const,
      startedAt: 1000,
      durationMs: 5,
      request,
      response: {
        status,
        headers: {},
        bodyBytes: Buffer.byteLength(body),
        bodySha256: sha256Hex(body),
        mediaType: 'application/json',
      },
      body,
      ...(typeof rawRequestBody === 'string' ? { rawRequestBody } : {}),
    })
  }
  const control = mk('control', JSON.stringify({ rendered: 'welcome page for the member dashboard template' }), 200)
  const probes = probeBodies.map((body, i) => {
    const rawRequestBody = JSON.stringify({ template: `{{ member_template_slot_${i} }}`, note: `render request ${i}` })
    return mk('probe', body, probeStatus, rawRequestBody)
  })
  return { store, controlId: control.exchangeId, probeIds: probes.map(p => p.exchangeId) }
}

test('host_evaluated_expression: host-minted challenge oracle verifies computed output across control/probe with leakage and reflection guards', () => {
  // (a) Single host-minted challenge: probe computes it, control does not leak it, request never echoes it.
  const ch = defaultHostMintedOracle.mintExpressionChallenge('ssti')
  const probeBody = JSON.stringify({ rendered: `rendered marker ${ch.expectedOutput} ok` })
  const fx = buildHeeStoreFixture([probeBody])
  const claim = {
    kind: 'host_evaluated_expression' as const,
    controlIds: [fx.controlId],
    probeIds: fx.probeIds,
    hostMintedChallengeIds: [ch.challengeId],
  }
  const res = evaluateClaim(fx.store, claim, {})
  assert.equal(res.passed, true, res.detail)
  assert.match(res.detail, /ssti/)
  assert.equal((res.observed as { family?: string }).family, 'ssti')
  assert.equal((res.observed as { challengeCount?: number }).challengeCount, 1)

  // (b) Unknown / unregistered challenge ids fail closed.
  const unknown = evaluateClaim(fx.store, { ...claim, hostMintedChallengeIds: ['expr_does_not_exist'] }, {})
  assert.equal(unknown.passed, false)
  assert.equal((unknown.observed as { rejectedBy?: string }).rejectedBy, 'host_evaluated_expression')
  assert.deepEqual(describeMissingEvidence(unknown), ['host_minted_expression_oracle'])

  // (c) Control leakage: the computed output appears in the control body -> fail closed.
  const leakyControlBody = JSON.stringify({ rendered: `cached banner ${ch.expectedOutput}` })
  const leakStore = new TranscriptStore()
  const mkLeak = (role: 'control' | 'probe', body: string, rawRequestBody?: string) => {
    const request = {
      origin: ORIGIN, method: role === 'probe' ? 'POST' : 'GET',
      pathAndQuery: role === 'probe' ? '/api/v1/render' : '/api/v1/render?view=control',
      headers: {}, bodyBytes: 0, bodySha256: sha256Hex(rawRequestBody ?? ''),
      sessionRole: role, nonce: `n-${role}-${Math.random().toString(36).slice(2, 8)}`,
    }
    return leakStore.record({
      op: 'http' as const, startedAt: 1000, durationMs: 5, request,
      response: { status: 200, headers: {}, bodyBytes: Buffer.byteLength(body), bodySha256: sha256Hex(body), mediaType: 'application/json' },
      body, ...(rawRequestBody !== undefined ? { rawRequestBody } : {}),
    })
  }
  const leakCtl = mkLeak('control', leakyControlBody)
  const leakPrb = mkLeak('probe', probeBody, JSON.stringify({ template: '{{ member_template_slot }}' }))
  const leakRes = evaluateClaim(leakStore, {
    kind: 'host_evaluated_expression', controlIds: [leakCtl.exchangeId], probeIds: [leakPrb.exchangeId],
    hostMintedChallengeIds: [ch.challengeId],
  }, {})
  assert.equal(leakRes.passed, false, 'control-arm leakage of the computed output must fail')

  // (d) Reflection: the computed output echoed in the probe request -> fail closed.
  const reflectStore = buildHeeStoreFixture([probeBody])
  const reflectProbe = reflectStore.store.record({
    op: 'http' as const, startedAt: 1000, durationMs: 5,
    request: {
      origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/render',
      headers: {}, bodyBytes: 0, bodySha256: sha256Hex(''), sessionRole: 'probe', personaHandle: 'member_a', nonce: 'n-reflect',
    },
    response: { status: 200, headers: {}, bodyBytes: Buffer.byteLength(probeBody), bodySha256: sha256Hex(probeBody), mediaType: 'application/json' },
    body: probeBody,
    rawRequestBody: JSON.stringify({ template: `{{ marker_${ch.expectedOutput} }}` }),
  })
  const reflectRes = evaluateClaim(reflectStore.store, {
    kind: 'host_evaluated_expression', controlIds: [reflectStore.controlId], probeIds: [reflectProbe.exchangeId],
    hostMintedChallengeIds: [ch.challengeId],
  }, {})
  assert.equal(reflectRes.passed, false, 'reflected (request-echoed) output must fail')

  // (e) Non-2xx probe or missing computed output fail closed.
  const errFx = buildHeeStoreFixture([JSON.stringify({ rendered: 'nothing computed here' })], 500)
  const errRes = evaluateClaim(errFx.store, { ...claim, probeIds: errFx.probeIds }, {})
  assert.equal(errRes.passed, false, 'non-2xx probes must fail')
  const absentFx = buildHeeStoreFixture([JSON.stringify({ rendered: 'no marker at all' })])
  const absentRes = evaluateClaim(absentFx.store, { ...claim, probeIds: absentFx.probeIds }, {})
  assert.equal(absentRes.passed, false, 'absent computed output must fail')
})

test('host_evaluated_expression: varying multi-challenge operands pass, repeated non-varying operands fail, and the claim is a first-class terminal oracle', () => {
  // (a) Two independently minted challenges with per-probe outputs.
  const ch1 = defaultHostMintedOracle.mintExpressionChallenge('ssti')
  const ch2 = defaultHostMintedOracle.mintExpressionChallenge('ssti')
  const fx = buildHeeStoreFixture([
    JSON.stringify({ rendered: `marker a ${ch1.expectedOutput}` }),
    JSON.stringify({ rendered: `marker b ${ch2.expectedOutput}` }),
  ])
  const claim = {
    kind: 'host_evaluated_expression' as const,
    controlIds: [fx.controlId],
    probeIds: fx.probeIds,
    hostMintedChallengeIds: [ch1.challengeId, ch2.challengeId],
  }
  const res = evaluateClaim(fx.store, claim, {})
  assert.equal(res.passed, true, res.detail)
  assert.equal((res.observed as { challengeCount?: number }).challengeCount, 2)

  // (b) Repeating the same challenge for two probes is non-varying operand laundering -> fail.
  const repeatRes = evaluateClaim(fx.store, { ...claim, hostMintedChallengeIds: [ch1.challengeId, ch1.challengeId] }, {})
  assert.equal(repeatRes.passed, false, 'repeated identical operands across probes must fail')

  // (c) evaluateClaims: a passing host_evaluated_expression claim alone carries the whole oracle verdict.
  const oracle = evaluateClaims(fx.store, [claim])
  assert.equal(oracle.passed, true, JSON.stringify(oracle.failures))
  assert.equal(oracle.rejectedBy, null)
  assert.equal(oracle.checks.length, 1)

  // (d) causalFingerprints exposes the host_evaluated_expression fingerprint for cross-attempt diffing.
  const prints = causalFingerprints(fx.store, oracle.checks, 'nonce-sys-host-autodag')
  assert.equal(prints.length, 1)
  const heePrint = prints[0]! as unknown as {
    kind: string
    expectation: { vulnClass: unknown; challenges: number }
    observed: { passed: boolean; family: string }
  }
  assert.equal(heePrint.kind, 'host_evaluated_expression')
  assert.equal(heePrint.expectation.vulnClass, null)
  assert.deepEqual(heePrint.observed, { passed: true, family: 'ssti' })

  // (e) A failing host_evaluated_expression claim fails the whole oracle and names the rejector.
  const failOracle = evaluateClaims(fx.store, [{ ...claim, hostMintedChallengeIds: ['expr_missing_forever'] }])
  assert.equal(failOracle.passed, false)
  assert.equal(failOracle.rejectedBy, 'host_evaluated_expression')
  assert.ok((failOracle.missingEvidence ?? []).includes('host_minted_expression_oracle'))
})

// ============================================================================
// 6. SDK Claim Custody: failed prove_* calls never poison ctx.claims
// ============================================================================

function json(res: ServerResponse, status: number, value: unknown, headers: Record<string, string> = {}): void {
  const body = JSON.stringify(value)
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), ...headers })
  res.end(body)
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks).toString('utf8')
}

function bindEnv(server: VerifyRpcServer): () => void {
  const keys = [VERIFY_RPC_SOCKET_ENV, VERIFY_RPC_TOKEN_ENV, VERIFY_RPC_CONTEXT_ENV, VERIFY_NONCE_ENV] as const
  const prev = keys.map(k => process.env[k])
  process.env[VERIFY_RPC_SOCKET_ENV] = server.socketPath
  process.env[VERIFY_RPC_TOKEN_ENV] = join(server.hostDir, 'token')
  process.env[VERIFY_RPC_CONTEXT_ENV] = join(server.hostDir, 'context.json')
  process.env[VERIFY_NONCE_ENV] = server.nonce
  return () => keys.forEach((k, i) => { if (prev[i] === undefined) delete process.env[k]; else process.env[k] = prev[i] })
}

async function startLiveFixture(t: test.TestContext): Promise<{ origin: string; server: VerifyRpcServer }> {
  const SESSION_TOK = 'live-session-tok-member-a-sys-001'
  const JOB_HANDLE = 'job-sys-host-autodag-888'
  const httpServer = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/login' && req.method === 'POST') {
      return json(res, 200, { token: SESSION_TOK }, { 'set-cookie': `sid=${SESSION_TOK}; Path=/; HttpOnly` })
    }
    if (url.pathname === '/api/v1/jobs' && req.method === 'POST') {
      if (req.headers.authorization !== `Bearer ${SESSION_TOK}`) return json(res, 401, { error: 'unauth' })
      return json(res, 200, { jobId: JOB_HANDLE })
    }
    if (url.pathname === `/api/v1/jobs/${JOB_HANDLE}/export` && req.method === 'GET') {
      if (req.headers.authorization !== `Bearer ${SESSION_TOK}`) return json(res, 403, { error: 'forbidden' })
      return json(res, 200, { tenantId: 'org_victim', records: [{ id: 'v-1', balance: 7700 }] })
    }
    if (url.pathname === '/api/v1/jobs/denied/export' && req.method === 'GET') {
      return json(res, 403, { error: 'forbidden' })
    }
    return json(res, 404, { error: 'not found' })
  })
  const port = await new Promise<number>((resolvePort, reject) => {
    httpServer.once('error', reject)
    httpServer.listen(0, '127.0.0.1', () => {
      const addr = httpServer.address()
      if (!addr || typeof addr === 'string') reject(new Error('no port'))
      else resolvePort(addr.port)
    })
  })
  const origin = `http://127.0.0.1:${port}`
  t.after(() => new Promise<void>(r => { httpServer.closeAllConnections(); httpServer.close(() => r()) }))

  const actor: ResolvedPersona = {
    id: 'persona-member-a',
    handle: 'member_a',
    roleLabel: 'member (org_a)',
    originAllowlist: [origin],
    authKind: 'header',
    headerName: 'X-User',
    secret: 'member-a-live-secret-01',
    canaryMarkers: [],
  }
  const grant: Grant = {
    origin,
    tier: 3,
    allowLocalLab: true,
    allowedPorts: [port],
    maxRpsPerOrigin: 200,
    personas: new Map([['member_a', actor]]),
    canRead: candidate => candidate === origin,
    isStateChangeApproved: () => true,
    audit: () => {},
  }
  const server = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant,
    runId: `run-sys-host-autodag-${randomUUID().slice(0, 8)}`,
    assignmentId: 'assign-sys-host-autodag',
    targetOrigins: [origin],
  })
  await server.start()
  t.after(() => server.close())
  const restore = bindEnv(server)
  t.after(restore)
  return { origin, server }
}

test('Live SDK: failed prove_composite never poisons ctx.claims; the failure surfaces only via the effectiveClaims fallback, then clears on success', async t => {
  const { origin, server } = await startLiveFixture(t)
  const ctx = new VerifyContext()

  // Login and seal the bearer session capability.
  const loginEx = await ctx.http_send('/login', { as: 'member_a', role: 'setup', method: 'POST' })
  assert.equal(loginEx.status, 200)
  const sessionCap = await ctx.seal_capability({ exchangeId: loginEx, hopReceiptId: 'setup', slot: 'tok', jsonPath: '$.token', kind: 'bearer_token' })
  assert.match(sessionCap.handle, /^cap:/)

  // (a) Deliberately FAILING composite: terminal probe hits the always-denied twin route (403).
  const doomedTerminal = await ctx.http_send('/api/v1/jobs/denied/export', {
    as: 'member_a', role: 'probe', capability: { handle: sessionCap.handle, target: 'bearer' },
  })
  assert.equal(doomedTerminal.status, 403)
  const setupJob = await ctx.http_send('/api/v1/jobs', {
    as: 'member_a', role: 'setup', method: 'POST', capability: { handle: sessionCap.handle, target: 'bearer' },
  })
  assert.equal(setupJob.status, 200)
  const failed = await ctx.prove_composite({
    chainId: 'sdk-lastfailed-negative',
    terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', target: { origin: ctx.targetOrigin, method: 'POST', path: '/api/v1/jobs' } as never, exchangeIds: [setupJob as never], claimedDelta: 'Created job.', producedCapabilities: [] },
      { hopId: 'hop_2', target: { origin: ctx.targetOrigin, method: 'GET', path: '/api/v1/jobs/denied/export' } as never, exchangeIds: [doomedTerminal as never], claimedDelta: 'Denied twin terminal probe.' },
    ],
    edges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: sessionCap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Hardened twin must not confirm.',
      terminalExchangeId: doomedTerminal as never,
    },
  } as never)
  assert.equal(failed.confirmed, false, 'the denied-twin receipt must not confirm')
  assert.equal(failed.ok, false)
  assert.equal(failed.verified, false)

  // (b) The failure NEVER lands in ctx.claims...
  assert.equal(ctx.claims.length, 0, `failed prove_* calls must not poison ctx.claims, got ${JSON.stringify(ctx.claims)}`)
  // ...but stays diagnosable through the _lastFailedClaims fallback.
  const fallback = ctx.effectiveClaims()
  assert.equal(fallback.length, 1, `expected exactly the failed composite claim as fallback, got ${JSON.stringify(fallback)}`)
  const fallbackClaim = fallback[0] as { kind: string; chainId?: string; rejectedBy?: string | null }
  assert.equal(fallbackClaim.kind, 'composite_receipt')
  assert.equal(fallbackClaim.chainId, 'sdk-lastfailed-negative')
  assert.equal(fallbackClaim.rejectedBy, 'composite_receipt')

  // (c) A subsequent SUCCESSFUL chain lands in ctx.claims and clears the failed-claim fallback.
  const chain = ctx.chain('live-sys-host-autodag-ok', 'cross_tenant_read')
  const h1 = await chain.hop('hop_1', { claimedDelta: 'Created export job in setup hop.' }, () =>
    ctx.http_send('/api/v1/jobs', { as: 'member_a', role: 'setup', method: 'POST', capability: { handle: sessionCap.handle, target: 'bearer' } }),
  )
  assert.equal(h1.status, 200)
  const jobCap = await ctx.seal_capability({ exchange: h1, slot: 'job_id', jsonPath: '$.jobId' })
  const ctrl = await ctx.http_send(`/api/v1/jobs/${jobCap.handle}/export`, { as: 'member_a', role: 'control' })
  assert.equal(ctrl.status, 403)
  chain.control(ctrl)
  const h2 = await chain.hop('hop_2', { claimedDelta: 'Exported foreign tenant data.' }, () =>
    ctx.http_send(`/api/v1/jobs/${jobCap.handle}/export`, { as: 'member_a', role: 'probe', capability: { handle: sessionCap.handle, target: 'bearer' } }),
  )
  assert.equal(h2.status, 200)
  chain.readback(h2)
  const proved = await chain.prove({ claimedImpact: 'Cross-tenant export confirmed via setup hop + multi-cap binding.' })
  assert.equal(proved.confirmed, true, `Expected live chain.prove() to confirm, got: ${JSON.stringify(server.transcript.latestCompositeVerification())}`)

  assert.ok(ctx.claims.length >= 1, 'the successful proof must be recorded in ctx.claims')
  const chainIds = ctx.claims.filter(c => c.kind === 'composite_receipt').map(c => (c as { chainId?: string }).chainId)
  assert.ok(chainIds.includes('live-sys-host-autodag-ok'), `expected the confirming chain claim, got ${JSON.stringify(chainIds)}`)
  assert.ok(!chainIds.includes('sdk-lastfailed-negative'), 'the failed chain claim must never enter ctx.claims')
  assert.deepEqual(ctx.effectiveClaims(), [...ctx.claims], 'after a success the fallback clears and effectiveClaims mirrors ctx.claims')
  assert.ok(origin.startsWith('http://127.0.0.1:'))
})

// ============================================================================
// 7. LOC Ceilings, Zero Dynamic RegExp, Anti-Contamination & Circular-Import Guards
// ============================================================================

test('LOC ceilings hold, zero dynamic new RegExp(), zero benchmark literals, and Auto-DAG imports stay type-only', () => {
  const files = {
    autodag: join(REPO_ROOT, 'src/server/composite-autodag.ts'),
    compositeReceipt: join(REPO_ROOT, 'src/server/composite-receipt.ts'),
    hostFactLog: join(REPO_ROOT, 'src/server/host-fact-log.ts'),
    agentScriptProof: join(REPO_ROOT, 'src/server/agent-script-proof.ts'),
    v8OracleHydrate: join(REPO_ROOT, 'src/server/v8-oracle-hydrate.ts'),
    verifyClaims: join(REPO_ROOT, 'src/server/verify-claims.ts'),
    kovoVerify: join(REPO_ROOT, 'worker/kovo_verify/kovo_verify.ts'),
  }
  const src = Object.fromEntries(Object.entries(files).map(([k, p]) => [k, readFileSync(p, 'utf8')])) as Record<keyof typeof files, string>
  const loc = (key: keyof typeof files): number => src[key].trimEnd().split('\n').length

  // LOC ceilings (composite-autodag is the new module; the others are the stream's bounded surfaces).
  assert.ok(loc('autodag') <= 400, `composite-autodag.ts=${loc('autodag')} > 400`)
  assert.ok(loc('compositeReceipt') <= 750, `composite-receipt.ts=${loc('compositeReceipt')} > 750`)
  assert.ok(loc('verifyClaims') <= 2300, `verify-claims.ts=${loc('verifyClaims')} > 2300`)
  assert.ok(loc('kovoVerify') <= 800, `kovo_verify.ts=${loc('kovoVerify')} > 800`)
  // v8-oracle-hydrate.ts is a PRE-EXISTING ~1553-LOC shared kernel (the stream only added the
  // 5-line GLOBAL_PRIV_LABEL_RE H-11 hardening). The guard pins no further growth from this stream.
  assert.ok(loc('v8OracleHydrate') <= 1558, `v8-oracle-hydrate.ts=${loc('v8OracleHydrate')} > 1558`)

  for (const key of Object.keys(src) as Array<keyof typeof files>) {
    assert.equal(/\bnew\s+RegExp\s*\(/.test(src[key]), false, `${key} must not use dynamic new RegExp()`)
    for (const forbidden of ['paygrid', 'shipforge', 'nexusiam', 'connecthub']) {
      assert.equal(src[key].toLowerCase().includes(forbidden), false, `${key} must not contain benchmark literal "${forbidden}"`)
    }
  }

  // Circular-import guard: composite-autodag must consume composite-receipt types only,
  // while composite-receipt wires the Auto-DAG augmentation as a runtime import.
  assert.equal(/^import\s+\{[^}]*\}\s+from\s+'\.\/composite-receipt\.ts'/m.test(src.autodag), false,
    'composite-autodag.ts must import composite-receipt types only (no runtime circular import)')
  assert.ok(/import \{ augmentCompositeReceiptWithAutoDag[^}]*\} from '\.\/composite-autodag\.ts'/.test(src.compositeReceipt),
    'composite-receipt.ts must keep the Auto-DAG augmentation wired')
})
