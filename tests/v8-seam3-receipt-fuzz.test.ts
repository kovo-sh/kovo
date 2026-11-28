/**
 * Seam 3 (`v8-seam3-receipt-fuzz`) — Automated Adversarial Receipt Mutation Fuzzer.
 *
 * Verifies 100% fail-closed soundness and zero secret leakage across:
 *   - `src/server/composite-receipt.ts` (all 4 causal edge bindings, DAG topology, signatures, provenance, Mode-A/B, terminal impact)
 *   - `src/server/v8-oracle-families.ts` (all 6 V8_ORACLE_FAMILIES)
 *   - `src/server/proof-receipt.ts` (single-hop ProofReceipt + `singleReceiptToComposite` bridge)
 *   - `src/server/verify-claims.ts` (`TranscriptStore`, `evaluateClaims`, `causalFingerprints`)
 *   - `src/server/verify-rpc.ts` & `src/server/verify-runner.ts` (`VerifyRpcServer`, `verifyScript` dual-replay agreement, secret scrubbing)
 *
 * All fixtures are 100% generic (zero benchmark names or literals) and execute in < 3 seconds.
 */
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import { scanTextForContamination } from '../scripts/check-v8-contamination.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  CAUSAL_EDGE_KINDS,
  sha256Hex,
  signHostRecord,
  singleReceiptToComposite,
  verifyCompositeReceipt,
} from '../src/server/composite-receipt.ts'
import type {
  CompositeProofReceipt,
  CompositeVerifyOptions,
  HostAsyncPollRecord,
  HostBrowserTrace,
  HostCryptoAttestation,
  HostOobEvent,
  HostSignedTranscript,
  HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { DerivedCapabilityVault, scrubDerivedSecrets } from '../src/server/derived-custody.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { verifyReceipt } from '../src/server/proof-receipt.ts'
import type { ProofReceipt } from '../src/server/proof-receipt.ts'
import { redact, redactHeaders, redactJsonValue } from '../src/server/redact.ts'
import type { V8OracleFamily } from '../src/server/v8-oracle-families.ts'
import {
  TranscriptStore,
  causalFingerprints,
  evaluateClaims,
} from '../src/server/verify-claims.ts'
import type { VerifyClaim } from '../src/server/verify-claims.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import { verifyScript } from '../src/server/verify-runner.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const ORIGIN_API = 'https://api.example.test'
const ORIGIN_APP = 'https://app.example.test'
const ORIGIN_IDP = 'https://idp.example.test'
const SIGNING_KEY = 'host-hmac-signing-key-fuzz-sentinel-7f3a91c0e4b2'

const ALL_V8_FAMILIES: readonly V8OracleFamily[] = [
  'dual_tenant_abac',
  'temporal_revocation',
  'economic_conservation',
  'cryptographic_scope_replay',
  'parser_cache_differential',
  'cross_surface_pivot',
] as const

// ============================================================================
// Generic Builders & Deep Clone / Signing Helpers
// ============================================================================

interface BaselineFixture {
  name: string
  receipt: CompositeProofReceipt
  transcript: HostSignedTranscript
  options: CompositeVerifyOptions
}

function deepClone<T>(value: T): T {
  return structuredClone(value)
}

function makeStep(
  partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>,
): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: partial.actor ?? {
      handle: 'member_alpha',
      role: 'member',
      tenant: 'org-alpha',
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
    ...(partial.secretMatches !== undefined ? { secretMatches: partial.secretMatches } : {}),
    ...(partial.evidenceRole !== undefined ? { evidenceRole: partial.evidenceRole } : {}),
    ...(partial.durationMs !== undefined ? { durationMs: partial.durationMs } : {}),
  }
}

function makeEntry(
  exchangeId: string,
  step: ImpactStep,
  extra: Partial<HostTranscriptEntry> = {},
): HostTranscriptEntry {
  return {
    exchangeId,
    step,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
}

function signTranscript(transcript: HostSignedTranscript, key = SIGNING_KEY): HostSignedTranscript {
  return {
    entries: (transcript.entries ?? []).map(e => ({ ...e, hostSignature: signHostRecord(e, key) })),
    oobEvents: (transcript.oobEvents ?? []).map(o => ({ ...o, hostSignature: signHostRecord(o, key) })),
    browserTraces: (transcript.browserTraces ?? []).map(t => ({ ...t, hostSignature: signHostRecord(t, key) })),
    asyncPollRecords: (transcript.asyncPollRecords ?? []).map(p => ({ ...p, hostSignature: signHostRecord(p, key) })),
  }
}

function assertNoSigningKeyLeak(result: unknown, key = SIGNING_KEY): void {
  const serialized = JSON.stringify(result)
  assert.equal(serialized.includes(key), false, 'signingKey leaked into verification output')
}

// ============================================================================
// Baseline Factories — All 4 Causal Edges + All 6 V8 Oracle Families + Single-Hop
// ============================================================================

function buildValueBindingBaseline(): BaselineFixture {
  const cap = 'cap:hop_1:delegated_tok'
  const rawToken = 'opaque_session_val_84729104'
  const valueDigest = sha256Hex(rawToken)
  const transcript = signTranscript({
    entries: [
      makeEntry('ex-vb-ctrl', makeStep({
        id: 'ex-vb-ctrl', arm: 'control', method: 'GET', status: 403,
        route: '/api/records/rec-900', pathAndQuery: '/api/records/rec-900',
      }), { timestampMs: 900, actorPersona: 'member_alpha' }),
      makeEntry('ex-vb-1', makeStep({
        id: 'ex-vb-1', arm: 'probe', method: 'GET', status: 200,
        route: '/api/session/export-token', pathAndQuery: '/api/session/export-token',
        json: { issuedHandle: rawToken },
      }), {
        timestampMs: 1000, actorPersona: 'member_alpha',
        emittedCapabilities: [cap], observedResponseDigests: [valueDigest],
      }),
      makeEntry('ex-vb-2', makeStep({
        id: 'ex-vb-2', arm: 'probe', method: 'GET', status: 200,
        route: '/api/records/rec-900', pathAndQuery: '/api/records/rec-900',
        requestHeaders: { Authorization: `Bearer ${rawToken}` },
        json: { id: 'rec-900', tenantId: 'org-beta', ownerEmail: 'owner@beta.example.test', balanceCents: 450000 },
      }), {
        timestampMs: 1600, actorPersona: null,
        consumedCapabilities: [cap], injectedRequestDigests: [valueDigest],
      }),
    ],
  })
  const receipt: CompositeProofReceipt = {
    chainId: 'chain-base-value-binding',
    terminalVulnClass: 'cross_tenant_read',
    hops: [
      {
        hopId: 'hop_1', surface: 'http',
        target: { origin: ORIGIN_API, method: 'GET', pathAndQuery: '/api/session/export-token' },
        exchangeIds: ['ex-vb-1'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Obtained delegated capability token',
        producedCapabilities: [cap], consumedCapabilities: [],
      },
      {
        hopId: 'hop_2', surface: 'http',
        target: { origin: ORIGIN_API, method: 'GET', pathAndQuery: '/api/records/rec-900' },
        exchangeIds: ['ex-vb-2'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Read foreign tenant record using delegated capability',
        producedCapabilities: [], consumedCapabilities: [cap],
      },
    ],
    causalEdges: [{
      kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2',
      capabilityHandle: cap, valueDigest,
      sourceExchangeId: 'ex-vb-1', targetExchangeId: 'ex-vb-2',
    }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Unauthorized read of foreign tenant record via delegated handle.',
      summary: 'Unauthorized read of foreign tenant record via delegated handle.',
      terminalExchangeId: 'ex-vb-2',
      preChainControlExchangeIds: ['ex-vb-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  return {
    name: 'edge:value_binding',
    receipt,
    transcript,
    options: { attackerPersonas: ['member_alpha'], forbiddenShortcutPersonas: ['admin_beta', 'owner_beta'], signingKey: SIGNING_KEY },
  }
}

function buildDerivedCryptoBaseline(): BaselineFixture {
  const saltCap = 'cap:hop_1:hmac_secret'
  const mintedCap = 'cap:hop_2:forged_jwt'
  const att: HostCryptoAttestation = {
    derivedFromCapabilityId: saltCap,
    derivedCapabilityId: mintedCap,
    alg: 'HS256',
    artifactDigest: sha256Hex('derived-jwt-artifact-v1'),
    timestampMs: 1300,
  }
  const transcript = signTranscript({
    entries: [
      makeEntry('ex-dc-ctrl', makeStep({
        id: 'ex-dc-ctrl', arm: 'control', method: 'GET', status: 403,
        route: '/api/admin/ledger', pathAndQuery: '/api/admin/ledger',
      }), { timestampMs: 800, actorPersona: 'member_alpha' }),
      makeEntry('ex-dc-1', makeStep({
        id: 'ex-dc-1', arm: 'probe', method: 'GET', status: 200,
        route: '/api/debug/signing-config', pathAndQuery: '/api/debug/signing-config',
        json: { keyHint: 'redacted' },
      }), { timestampMs: 1000, actorPersona: 'member_alpha', emittedCapabilities: [saltCap] }),
      makeEntry('ex-dc-2', makeStep({
        id: 'ex-dc-2', arm: 'probe', method: 'POST', status: 200,
        route: '/idp/token/mint', pathAndQuery: '/idp/token/mint',
        json: { minted: true },
      }), {
        timestampMs: 1500, actorPersona: 'member_alpha',
        emittedCapabilities: [mintedCap], cryptoAttestations: [att],
      }),
      makeEntry('ex-dc-3', makeStep({
        id: 'ex-dc-3', arm: 'probe', method: 'GET', status: 200,
        route: '/api/admin/ledger', pathAndQuery: '/api/admin/ledger',
        json: { tenantId: 'org-beta', ledgerTotalCents: 990000, auditOwner: 'owner@beta.example.test' },
      }), { timestampMs: 2000, actorPersona: null, consumedCapabilities: [mintedCap] }),
    ],
  })
  const receipt: CompositeProofReceipt = {
    chainId: 'chain-base-derived-crypto',
    terminalVulnClass: 'authz_bypass',
    hops: [
      {
        hopId: 'hop_1', surface: 'http',
        target: { origin: ORIGIN_API, method: 'GET', pathAndQuery: '/api/debug/signing-config' },
        exchangeIds: ['ex-dc-1'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Extracted signing key capability',
        producedCapabilities: [saltCap], consumedCapabilities: [],
      },
      {
        hopId: 'hop_2', surface: 'idp',
        target: { origin: ORIGIN_IDP, method: 'POST', pathAndQuery: '/idp/token/mint' },
        exchangeIds: ['ex-dc-2'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Signed elevated JWT via Layer-1 crypto primitive',
        producedCapabilities: [mintedCap], consumedCapabilities: [],
      },
      {
        hopId: 'hop_3', surface: 'http',
        target: { origin: ORIGIN_API, method: 'GET', pathAndQuery: '/api/admin/ledger' },
        exchangeIds: ['ex-dc-3'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Accessed admin ledger with derived JWT',
        producedCapabilities: [], consumedCapabilities: [mintedCap],
      },
    ],
    causalEdges: [
      { kind: 'derived_crypto_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sourceCapabilityId: saltCap, derivedCapabilityId: mintedCap, alg: 'HS256' },
      { kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_3', capabilityHandle: mintedCap },
    ],
    terminalImpact: {
      terminalHopId: 'hop_3',
      claimedImpact: 'Read privileged cross-tenant ledger using derived HS256 token.',
      summary: 'Read privileged cross-tenant ledger using derived HS256 token.',
      terminalExchangeId: 'ex-dc-3',
      preChainControlExchangeIds: ['ex-dc-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  return {
    name: 'edge:derived_crypto_binding',
    receipt,
    transcript,
    options: { attackerPersonas: ['member_alpha'], forbiddenShortcutPersonas: ['admin_beta'], signingKey: SIGNING_KEY },
  }
}

function buildStateTransitionBaseline(): BaselineFixture {
  const entityId = 'order-4201'
  const transcript = signTranscript({
    entries: [
      makeEntry('ex-st-ablation', makeStep({
        id: 'ex-st-ablation', arm: 'control', method: 'POST', status: 403,
        route: `/api/orders/${entityId}/approve`, pathAndQuery: `/api/orders/${entityId}/approve`,
        json: { error: 'maker_checker_required' },
      }), { timestampMs: 900, actorPersona: 'member_alpha', entityId, cleanSession: true, replayAttempt: 'ablation_control' }),
      makeEntry('ex-st-1', makeStep({
        id: 'ex-st-1', arm: 'probe', method: 'PATCH', status: 200,
        route: `/api/orders/${entityId}`, pathAndQuery: `/api/orders/${entityId}`,
        json: { id: entityId, creatorId: 'other-user', state: 'primed' },
      }), { timestampMs: 1200, actorPersona: 'member_alpha', entityId }),
      makeEntry('ex-st-2', makeStep({
        id: 'ex-st-2', arm: 'probe', method: 'POST', status: 200,
        route: `/api/orders/${entityId}/approve`, pathAndQuery: `/api/orders/${entityId}/approve`,
        json: { id: entityId, approved: true, payoutCents: 180000 },
      }), { timestampMs: 1600, actorPersona: 'member_alpha', entityId }),
      makeEntry('ex-st-readback', makeStep({
        id: 'ex-st-readback', arm: 'control', method: 'GET', status: 200,
        route: `/api/orders/${entityId}`, pathAndQuery: `/api/orders/${entityId}`,
        json: { id: entityId, approved: true, payoutCents: 180000 },
        evidenceRole: 'post_chain_readback',
      }), { timestampMs: 1900, actorPersona: 'member_alpha', entityId }),
    ],
  })
  const receipt: CompositeProofReceipt = {
    chainId: 'chain-base-state-transition',
    terminalVulnClass: 'business_logic',
    hops: [
      {
        hopId: 'hop_1', surface: 'http',
        target: { origin: ORIGIN_API, method: 'PATCH', pathAndQuery: `/api/orders/${entityId}` },
        exchangeIds: ['ex-st-1'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Reassigned order creator metadata',
        producedCapabilities: [], consumedCapabilities: [], entityId,
      },
      {
        hopId: 'hop_2', surface: 'http',
        target: { origin: ORIGIN_API, method: 'POST', pathAndQuery: `/api/orders/${entityId}/approve` },
        exchangeIds: ['ex-st-2'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Self-approved order payout',
        producedCapabilities: [], consumedCapabilities: [], entityId,
      },
    ],
    causalEdges: [{
      kind: 'state_transition_binding', fromHopId: 'hop_1', toHopId: 'hop_2',
      entityId, ablationExchangeIds: ['ex-st-ablation'], mutationKind: 'maker_checker_prime',
    }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Bypassed maker-checker invariant via state transition on order.',
      summary: 'Bypassed maker-checker invariant via state transition on order.',
      terminalExchangeId: 'ex-st-2',
      preChainControlExchangeIds: ['ex-st-ablation'],
      postChainReadbackExchangeIds: ['ex-st-readback'],
    },
    replayMode: 'fresh_clean_replay',
  }
  return {
    name: 'edge:state_transition_binding',
    receipt,
    transcript,
    options: { attackerPersonas: ['member_alpha'], forbiddenShortcutPersonas: ['admin_beta'], signingKey: SIGNING_KEY },
  }
}

function buildAsyncPivotBaseline(channel: 'poll_convergence' | 'oob_relay' | 'browser_trace' | 'async_job' = 'poll_convergence'): BaselineFixture {
  const corr = 'corr-async-7741'
  const pollRec: HostAsyncPollRecord = {
    id: 'poll-ap-1',
    triggerExchangeId: 'ex-ap-1',
    tTriggerMs: 1000,
    tObservedMs: 1800,
    converged: true,
    correlationIds: [corr],
    entityId: corr,
  }
  const oobRec: HostOobEvent = {
    id: 'oob-ap-1',
    token: corr,
    delivered: true,
    receivedAtMs: 1700,
    correlationIds: [corr],
  }
  const traceRec: HostBrowserTrace = {
    id: 'trace-ap-1',
    origin: ORIGIN_APP,
    sinks: ['dom_xss'],
    timestampMs: 1750,
    correlationIds: [corr],
  }
  const transcript = signTranscript({
    entries: [
      makeEntry('ex-ap-1', makeStep({
        id: 'ex-ap-1', arm: 'probe', method: 'POST', status: 202,
        route: '/api/jobs/render', pathAndQuery: '/api/jobs/render',
        requestJson: { correlationId: corr },
        json: { jobId: 'job-99', correlationId: corr, status: 'queued' },
      }), { timestampMs: 1000, actorPersona: 'member_alpha', correlationIds: [corr] }),
      makeEntry('ex-ap-2', makeStep({
        id: 'ex-ap-2', arm: 'probe', method: 'GET', status: 200,
        route: `/api/jobs/output/${corr}`, pathAndQuery: `/api/jobs/output/${corr}`,
        json: { correlationId: corr, tenantId: 'org-beta', extractedRecord: 'secret-row-7' },
      }), { timestampMs: 2100, actorPersona: 'member_alpha', correlationIds: [corr] }),
    ],
    oobEvents: [oobRec],
    browserTraces: [traceRec],
    asyncPollRecords: [pollRec],
  })
  const toHopSurface = channel === 'oob_relay' ? 'webhook' : channel === 'browser_trace' ? 'browser' : 'async_job'
  const receipt: CompositeProofReceipt = {
    chainId: `chain-base-async-${channel}`,
    terminalVulnClass: channel === 'browser_trace' ? 'xss_stored' : 'ssrf',
    hops: [
      {
        hopId: 'hop_1', surface: 'http',
        target: { origin: ORIGIN_API, method: 'POST', pathAndQuery: '/api/jobs/render' },
        exchangeIds: ['ex-ap-1'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Queued async worker job with correlation token',
        producedCapabilities: [], consumedCapabilities: [],
      },
      {
        hopId: 'hop_2', surface: toHopSurface,
        target: { origin: ORIGIN_API, method: 'GET', pathAndQuery: `/api/jobs/output/${corr}` },
        exchangeIds: ['ex-ap-2'],
        oobEventIds: channel === 'oob_relay' ? ['oob-ap-1'] : [],
        browserTraceIds: channel === 'browser_trace' ? ['trace-ap-1'] : [],
        claimedDelta: `Observed async convergence via ${channel}`,
        producedCapabilities: [], consumedCapabilities: [],
      },
    ],
    causalEdges: [{
      kind: 'async_pivot_binding', fromHopId: 'hop_1', toHopId: 'hop_2',
      correlationId: corr, channel,
      ...(channel === 'poll_convergence' ? { pollRecordId: 'poll-ap-1' } : {}),
      ...(channel === 'oob_relay' ? { oobEventId: 'oob-ap-1' } : {}),
      ...(channel === 'browser_trace' ? { browserTraceId: 'trace-ap-1' } : {}),
    }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: `Confirmed async cross-surface impact over ${channel}.`,
      summary: `Confirmed async cross-surface impact over ${channel}.`,
      terminalExchangeId: 'ex-ap-2',
      preChainControlExchangeIds: [],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  return {
    name: `edge:async_pivot_binding:${channel}`,
    receipt,
    transcript,
    options: { attackerPersonas: ['member_alpha'], forbiddenShortcutPersonas: ['admin_beta'], signingKey: SIGNING_KEY },
  }
}

function buildDualTenantAbacBaseline(): BaselineFixture {
  const entityId = 'asset-501'
  const transcript = signTranscript({
    entries: [
      makeEntry('ex-dt-ctrl', makeStep({
        id: 'ex-dt-ctrl', arm: 'control', method: 'GET', status: 403,
        route: `/api/assets/${entityId}`, pathAndQuery: `/api/assets/${entityId}`,
      }), { timestampMs: 800, actorPersona: 'member_alpha', entityId }),
      makeEntry('ex-dt-transfer', makeStep({
        id: 'ex-dt-transfer', arm: 'probe', method: 'POST', status: 200,
        route: `/api/assets/${entityId}/transfer`, pathAndQuery: `/api/assets/${entityId}/transfer`,
        json: { id: entityId, ownerTenantId: 'org-alpha', moved: true },
      }), { timestampMs: 1200, actorPersona: 'member_alpha', entityId }),
      makeEntry('ex-dt-readback', makeStep({
        id: 'ex-dt-readback', arm: 'probe', method: 'GET', status: 200,
        route: `/api/assets/${entityId}`, pathAndQuery: `/api/assets/${entityId}`,
        json: { id: entityId, tenantId: 'org-beta', ownerTenantId: 'org-alpha', secretNote: 'confidential-beta-doc' },
      }), { timestampMs: 1600, actorPersona: 'member_alpha', entityId }),
    ],
  })
  const receipt: CompositeProofReceipt = {
    chainId: 'chain-oracle-dual-tenant-abac',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [{
      hopId: 'hop_1', surface: 'http',
      target: { origin: ORIGIN_API, method: 'GET', pathAndQuery: `/api/assets/${entityId}` },
      exchangeIds: ['ex-dt-transfer', 'ex-dt-readback'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Transferred org-beta asset to org-alpha without org-beta admin privilege',
      producedCapabilities: [], consumedCapabilities: [], entityId,
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      claimedImpact: 'Cross-org asset transfer persisted without source tenant authorization.',
      summary: 'Cross-org asset transfer persisted without source tenant authorization.',
      terminalExchangeId: 'ex-dt-readback',
      oracleFamily: 'dual_tenant_abac',
      oracleInput: {
        mode: 'cross_org_transfer',
        actor: { actorId: 'member_alpha', rolesByTenant: { 'org-alpha': 'admin', 'org-beta': 'viewer' } },
        sourceTenantId: 'org-beta',
        destTenantId: 'org-alpha',
        entityId,
        observedOwnerTenantId: 'org-alpha',
        sourceControlDenied: 'ex-dt-ctrl',
        transferRecord: 'ex-dt-transfer',
        postTransferReadback: 'ex-dt-readback',
      },
      preChainControlExchangeIds: ['ex-dt-ctrl'],
      postChainReadbackExchangeIds: ['ex-dt-readback'],
    },
    replayMode: 'fresh_clean_replay',
  }
  return {
    name: 'oracle:dual_tenant_abac',
    receipt,
    transcript,
    options: { attackerPersonas: ['member_alpha'], forbiddenShortcutPersonas: ['admin_beta'], signingKey: SIGNING_KEY },
  }
}

function buildTemporalRevocationBaseline(): BaselineFixture {
  const cap = 'cap:hop_1:pat_token'
  const transcript = signTranscript({
    entries: [
      makeEntry('ex-tr-gql-ctrl', makeStep({
        id: 'ex-tr-gql-ctrl', arm: 'control', method: 'POST', status: 403,
        route: '/graphql', pathAndQuery: '/graphql',
        json: { error: 'forbidden' },
      }), { timestampMs: 850, actorPersona: 'member_alpha' }),
      makeEntry('ex-tr-base', makeStep({
        id: 'ex-tr-base', arm: 'probe', method: 'GET', status: 200,
        route: '/api/profile', pathAndQuery: '/api/profile',
        json: { user: 'member_alpha', active: true },
      }), { timestampMs: 900, actorPersona: 'member_alpha', emittedCapabilities: [cap] }),
      makeEntry('ex-tr-revoke', makeStep({
        id: 'ex-tr-revoke', arm: 'control', method: 'POST', status: 200,
        route: '/api/tokens/revoke', pathAndQuery: '/api/tokens/revoke',
        json: { revoked: true },
      }), { timestampMs: 1200, actorPersona: 'member_alpha' }),
      makeEntry('ex-tr-denied', makeStep({
        id: 'ex-tr-denied', arm: 'control', method: 'GET', status: 401,
        route: '/api/profile', pathAndQuery: '/api/profile',
        json: { error: 'token_revoked' },
      }), { timestampMs: 1500, actorPersona: 'member_alpha', consumedCapabilities: [cap] }),
      makeEntry('ex-tr-secondary', makeStep({
        id: 'ex-tr-secondary', arm: 'probe', method: 'POST', status: 200,
        route: '/graphql', pathAndQuery: '/graphql',
        json: { data: { tenantSecrets: [{ id: 's1', tenantId: 'org-beta', value: 'exposed-after-revoke' }] } },
      }), { timestampMs: 1900, actorPersona: 'member_alpha', consumedCapabilities: [cap] }),
    ],
  })
  const receipt: CompositeProofReceipt = {
    chainId: 'chain-oracle-temporal-revocation',
    terminalVulnClass: 'temporal_revocation',
    hops: [
      {
        hopId: 'hop_1', surface: 'http',
        target: { origin: ORIGIN_API, method: 'GET', pathAndQuery: '/api/profile' },
        exchangeIds: ['ex-tr-base', 'ex-tr-revoke', 'ex-tr-denied'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Issued and revoked token; primary HTTP surface rejects it with 401',
        producedCapabilities: [cap], consumedCapabilities: [],
      },
      {
        hopId: 'hop_2', surface: 'graphql',
        target: { origin: ORIGIN_API, method: 'POST', pathAndQuery: '/graphql' },
        exchangeIds: ['ex-tr-secondary'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Revoked token still accepted on GraphQL secondary surface',
        producedCapabilities: [], consumedCapabilities: [cap],
      },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Revoked credential remained valid on secondary GraphQL surface.',
      summary: 'Revoked credential remained valid on secondary GraphQL surface.',
      terminalExchangeId: 'ex-tr-secondary',
      oracleFamily: 'temporal_revocation',
      oracleInput: {
        credentialKind: 'pat',
        credentialHandle: cap,
        actorId: 'member_alpha',
        primarySurface: 'http',
        secondarySurface: 'graphql',
        preRevocationBaseline: 'ex-tr-base',
        revocationEvent: 'ex-tr-revoke',
        primaryDeniedCheck: 'ex-tr-denied',
        secondarySuccess: 'ex-tr-secondary',
      },
      preChainControlExchangeIds: ['ex-tr-gql-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  return {
    name: 'oracle:temporal_revocation',
    receipt,
    transcript,
    options: { attackerPersonas: ['member_alpha'], forbiddenShortcutPersonas: ['admin_beta'], signingKey: SIGNING_KEY },
  }
}

function buildEconomicConservationBaseline(): BaselineFixture {
  const transcript = signTranscript({
    entries: [
      makeEntry('ex-ec-base', makeStep({
        id: 'ex-ec-base', arm: 'control', method: 'GET', status: 200,
        route: '/api/wallet/w-1', pathAndQuery: '/api/wallet/w-1',
        json: { walletId: 'w-1', paidAmount: 100, refundedTotal: 0 },
      }), { timestampMs: 1000, actorPersona: 'member_alpha' }),
      makeEntry('ex-ec-act1', makeStep({
        id: 'ex-ec-act1', arm: 'probe', method: 'POST', status: 200,
        route: '/api/wallet/w-1/refund', pathAndQuery: '/api/wallet/w-1/refund',
        json: { refunded: 80 },
      }), { timestampMs: 1300, actorPersona: 'member_alpha' }),
      makeEntry('ex-ec-act2', makeStep({
        id: 'ex-ec-act2', arm: 'probe', method: 'POST', status: 200,
        route: '/api/wallet/w-1/refund', pathAndQuery: '/api/wallet/w-1/refund',
        json: { refunded: 80 },
      }), { timestampMs: 1400, actorPersona: 'member_alpha' }),
      makeEntry('ex-ec-final', makeStep({
        id: 'ex-ec-final', arm: 'control', method: 'GET', status: 200,
        route: '/api/wallet/w-1', pathAndQuery: '/api/wallet/w-1',
        json: { walletId: 'w-1', paidAmount: 100, refundedTotal: 160 },
        evidenceRole: 'post_chain_readback',
      }), { timestampMs: 1800, actorPersona: 'member_alpha' }),
    ],
  })
  const receipt: CompositeProofReceipt = {
    chainId: 'chain-oracle-economic-conservation',
    terminalVulnClass: 'economic_conservation',
    hops: [{
      hopId: 'hop_1', surface: 'http',
      target: { origin: ORIGIN_API, method: 'POST', pathAndQuery: '/api/wallet/w-1/refund' },
      exchangeIds: ['ex-ec-act1', 'ex-ec-act2'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Issued duplicate refunds exceeding paid amount (160 > 100)',
      producedCapabilities: [], consumedCapabilities: [],
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      claimedImpact: 'Over-refund violated economic conservation: refunded 160 on 100 paid.',
      summary: 'Over-refund violated economic conservation: refunded 160 on 100 paid.',
      terminalExchangeId: 'ex-ec-act2',
      oracleFamily: 'economic_conservation',
      oracleInput: {
        equation: 'over_refund',
        paidAmount: 100,
        refundedAmounts: [80, 80],
        baselineRefunded: 0,
        baselineReadback: 'ex-ec-base',
        actions: ['ex-ec-act1', 'ex-ec-act2'],
        finalReadback: 'ex-ec-final',
      },
      preChainControlExchangeIds: ['ex-ec-base'],
      postChainReadbackExchangeIds: ['ex-ec-final'],
    },
    replayMode: 'fresh_clean_replay',
  }
  return {
    name: 'oracle:economic_conservation',
    receipt,
    transcript,
    options: { attackerPersonas: ['member_alpha'], forbiddenShortcutPersonas: ['admin_beta'], signingKey: SIGNING_KEY },
  }
}

function buildCryptoScopeReplayBaseline(): BaselineFixture {
  const validSigDigest = sha256Hex('valid-hmac-signature-org-alpha')
  const tamperedSigDigest = sha256Hex('tampered-hmac-signature-invalid')
  const cap = 'cap:hop_1:scoped_sig'
  const transcript = signTranscript({
    entries: [
      makeEntry('ex-cs-tampered', makeStep({
        id: 'ex-cs-tampered', arm: 'control', method: 'POST', status: 403,
        route: '/api/webhooks/apply', pathAndQuery: '/api/webhooks/apply',
        json: { error: 'invalid_signature' },
      }), { timestampMs: 900, actorPersona: 'member_alpha', observedResponseDigests: [tamperedSigDigest] }),
      makeEntry('ex-cs-issue', makeStep({
        id: 'ex-cs-issue', arm: 'probe', method: 'POST', status: 200,
        route: '/api/webhooks/sign', pathAndQuery: '/api/webhooks/sign',
        json: { issued: true, scope: 'read:alpha' },
      }), { timestampMs: 1200, actorPersona: 'member_alpha', emittedCapabilities: [cap], observedResponseDigests: [validSigDigest] }),
      makeEntry('ex-cs-replay', makeStep({
        id: 'ex-cs-replay', arm: 'probe', method: 'POST', status: 200,
        route: '/api/webhooks/apply', pathAndQuery: '/api/webhooks/apply',
        json: { applied: true, tenantId: 'org-beta', mutatedQuota: 9999 },
      }), { timestampMs: 1700, actorPersona: 'member_alpha', consumedCapabilities: [cap], observedResponseDigests: [validSigDigest] }),
    ],
  })
  const receipt: CompositeProofReceipt = {
    chainId: 'chain-oracle-crypto-scope-replay',
    terminalVulnClass: 'cryptographic_scope_replay',
    hops: [
      {
        hopId: 'hop_1', surface: 'http',
        target: { origin: ORIGIN_API, method: 'POST', pathAndQuery: '/api/webhooks/sign' },
        exchangeIds: ['ex-cs-issue'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Obtained validly signed token scoped to org-alpha',
        producedCapabilities: [cap], consumedCapabilities: [],
      },
      {
        hopId: 'hop_2', surface: 'http',
        target: { origin: ORIGIN_API, method: 'POST', pathAndQuery: '/api/webhooks/apply' },
        exchangeIds: ['ex-cs-replay'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Replayed org-alpha signature into org-beta admin scope',
        producedCapabilities: [], consumedCapabilities: [cap],
      },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Valid cryptographic signature replayed across tenant and scope boundary.',
      summary: 'Valid cryptographic signature replayed across tenant and scope boundary.',
      terminalExchangeId: 'ex-cs-replay',
      oracleFamily: 'cryptographic_scope_replay',
      oracleInput: {
        tamperedSignatureControl: 'ex-cs-tampered',
        sourceValidIssuance: 'ex-cs-issue',
        replayedAcceptance: 'ex-cs-replay',
        sourceTenant: 'org-alpha',
        sourceScope: 'read:alpha',
        targetTenant: 'org-beta',
        targetScope: 'write:beta',
        tamperedSignatureDigest: tamperedSigDigest,
        signatureDigest: validSigDigest,
        replayedSignatureDigest: validSigDigest,
      },
      preChainControlExchangeIds: ['ex-cs-tampered'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  return {
    name: 'oracle:cryptographic_scope_replay',
    receipt,
    transcript,
    options: { attackerPersonas: ['member_alpha'], forbiddenShortcutPersonas: ['admin_beta'], signingKey: SIGNING_KEY },
  }
}

function buildParserCacheBaseline(): BaselineFixture {
  const victimDigest = sha256Hex('victim-beta-private-statement-row-88')
  const transcript = signTranscript({
    entries: [
      makeEntry('ex-pc-ctrl', makeStep({
        id: 'ex-pc-ctrl', arm: 'control', method: 'GET', status: 403,
        route: '/api/statements/latest', pathAndQuery: '/api/statements/latest',
        json: { error: 'forbidden' },
      }), { timestampMs: 800, actorPersona: 'member_alpha' }),
      makeEntry('ex-pc-prime', makeStep({
        id: 'ex-pc-prime', arm: 'control', method: 'GET', status: 200,
        route: '/api/statements/latest', pathAndQuery: '/api/statements/latest',
        actor: { handle: 'member_beta', role: 'member', tenant: 'org-beta', auth: 'bearer', sameSite: null },
        json: { tenantId: 'org-beta', statementId: 'st-88', revenueCents: 712000 },
      }), { timestampMs: 1200, actorPersona: 'member_beta', observedResponseDigests: [victimDigest] }),
      makeEntry('ex-pc-probe', makeStep({
        id: 'ex-pc-probe', arm: 'probe', method: 'GET', status: 200,
        route: '/api/statements/latest', pathAndQuery: '/api/statements/latest',
        responseHeaders: { 'x-cache': 'HIT', age: '12' },
        json: { tenantId: 'org-beta', statementId: 'st-88', revenueCents: 712000 },
      }), { timestampMs: 1700, actorPersona: 'member_alpha', observedResponseDigests: [victimDigest] }),
    ],
  })
  const receipt: CompositeProofReceipt = {
    chainId: 'chain-oracle-parser-cache-diff',
    terminalVulnClass: 'parser_cache_differential',
    hops: [{
      hopId: 'hop_1', surface: 'cdn',
      target: { origin: ORIGIN_API, method: 'GET', pathAndQuery: '/api/statements/latest' },
      exchangeIds: ['ex-pc-probe'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Received victim tenant statement from shared CDN cache',
      producedCapabilities: [], consumedCapabilities: [],
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      claimedImpact: 'Shared cache bleed disclosed org-beta statement to org-alpha.',
      summary: 'Shared cache bleed disclosed org-beta statement to org-alpha.',
      terminalExchangeId: 'ex-pc-probe',
      oracleFamily: 'parser_cache_differential',
      oracleInput: {
        mode: 'cache_primed',
        cacheKey: 'GET:/api/statements/latest',
        victimArtifactDigest: victimDigest,
        cleanControl: 'ex-pc-ctrl',
        victimOrPrimeRequest: 'ex-pc-prime',
        attackerProbe: 'ex-pc-probe',
        cacheHitObserved: true,
      },
      preChainControlExchangeIds: ['ex-pc-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  return {
    name: 'oracle:parser_cache_differential',
    receipt,
    transcript,
    options: { attackerPersonas: ['member_alpha'], forbiddenShortcutPersonas: ['admin_beta'], signingKey: SIGNING_KEY },
  }
}

function buildCrossSurfacePivotBaseline(): BaselineFixture {
  const cap = 'cap:hop_1:browser_session'
  const transcript = signTranscript({
    entries: [
      makeEntry('ex-csp-ctrl', makeStep({
        id: 'ex-csp-ctrl', arm: 'control', method: 'GET', status: 403,
        route: '/api/internal/config', pathAndQuery: '/api/internal/config',
        json: { error: 'forbidden' },
      }), { timestampMs: 700, actorPersona: 'member_alpha' }),
      makeEntry('ex-csp-1', makeStep({
        id: 'ex-csp-1', arm: 'probe', method: 'POST', status: 200,
        route: '/api/notes', pathAndQuery: '/api/notes',
        json: { noteId: 'n-1', stored: true },
      }), { timestampMs: 1000, actorPersona: 'member_alpha', emittedCapabilities: [cap] }),
      makeEntry('ex-csp-2', makeStep({
        id: 'ex-csp-2', arm: 'probe', method: 'GET', status: 200,
        route: '/api/internal/config', pathAndQuery: '/api/internal/config',
        json: { tenantId: 'org-beta', internalEndpoint: 'https://ops.example.test/v2', auditKeyId: 'k-88' },
      }), { timestampMs: 1900, actorPersona: null, consumedCapabilities: [cap] }),
    ],
  })
  const receipt: CompositeProofReceipt = {
    chainId: 'chain-oracle-cross-surface-pivot',
    terminalVulnClass: 'cross_surface_pivot',
    hops: [
      {
        hopId: 'hop_1', surface: 'browser',
        target: { origin: ORIGIN_APP, method: 'POST', pathAndQuery: '/api/notes' },
        exchangeIds: ['ex-csp-1'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Triggered browser surface capture of delegated session capability',
        producedCapabilities: [cap], consumedCapabilities: [],
      },
      {
        hopId: 'hop_2', surface: 'http',
        target: { origin: ORIGIN_API, method: 'GET', pathAndQuery: '/api/internal/config' },
        exchangeIds: ['ex-csp-2'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Pivoted to HTTP API surface to read restricted config',
        producedCapabilities: [], consumedCapabilities: [cap],
      },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Cross-surface pivot from browser to HTTP API read restricted tenant config.',
      summary: 'Cross-surface pivot from browser to HTTP API read restricted tenant config.',
      terminalExchangeId: 'ex-csp-2',
      oracleFamily: 'cross_surface_pivot',
      preChainControlExchangeIds: ['ex-csp-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  return {
    name: 'oracle:cross_surface_pivot',
    receipt,
    transcript,
    options: { attackerPersonas: ['member_alpha'], forbiddenShortcutPersonas: ['admin_beta'], signingKey: SIGNING_KEY },
  }
}

function buildSingleHopProofReceipts(): Array<{ name: string; proof: ProofReceipt; transcript: HostSignedTranscript }> {
  // 1. BOLA cross-tenant disclosure
  const bolaProof: ProofReceipt = {
    vulnClass: 'bola',
    target: { origin: ORIGIN_API, method: 'GET', pathAndQuery: '/api/invoices/inv-77' },
    exchangeIds: ['sh-bola-ctrl', 'sh-bola-probe'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'Member in org-alpha read org-beta invoice inv-77',
    resourceTenant: 'org-beta',
  }
  const bolaTranscript = signTranscript({
    entries: [
      makeEntry('sh-bola-ctrl', makeStep({
        id: 'sh-bola-ctrl', arm: 'control', method: 'GET', status: 403,
        route: '/api/invoices/inv-77', pathAndQuery: '/api/invoices/inv-77',
        json: { error: 'forbidden' },
      }), { timestampMs: 1000, actorPersona: 'member_alpha' }),
      makeEntry('sh-bola-probe', makeStep({
        id: 'sh-bola-probe', arm: 'probe', method: 'GET', status: 200,
        route: '/api/invoices/inv-77', pathAndQuery: '/api/invoices/inv-77',
        json: { id: 'inv-77', tenantId: 'org-beta', ownerId: 'usr-beta-9', email: 'finance@beta.example.test', totalCents: 99000 },
      }), { timestampMs: 1200, actorPersona: 'member_alpha' }),
    ],
  })

  // 2. OOB SSRF durable callback
  const canaryToken = 'canary-oob-928371'
  const oobProof: ProofReceipt = {
    vulnClass: 'ssrf',
    target: { origin: ORIGIN_API, method: 'POST', pathAndQuery: '/api/fetch-preview' },
    exchangeIds: ['sh-oob-ex'],
    oobEventIds: ['sh-oob-evt'],
    browserTraceIds: [],
    claimedDelta: 'Target server fetched injected out-of-band canary URL',
    injectedAtMs: 1000,
  }
  const oobTranscript = signTranscript({
    entries: [
      makeEntry('sh-oob-ex', makeStep({
        id: 'sh-oob-ex', arm: 'probe', method: 'POST', status: 200,
        route: '/api/fetch-preview', pathAndQuery: '/api/fetch-preview',
        requestJson: { url: `https://relay.example.test/${canaryToken}` },
        json: { ok: true },
      }), { timestampMs: 1000, actorPersona: 'member_alpha', carrierText: `https://relay.example.test/${canaryToken}` }),
    ],
    oobEvents: [{
      id: 'sh-oob-evt',
      token: canaryToken,
      targetOrigin: ORIGIN_API,
      delivered: true,
      stage: 'immediate',
      receivedAtMs: 1350,
      injectedAtMs: 1000,
      latencyMs: 350,
    }],
  })

  // 3. Open redirect
  const redirectProof: ProofReceipt = {
    vulnClass: 'open_redirect',
    target: { origin: ORIGIN_API, method: 'GET', pathAndQuery: '/login?next=https://external.example.invalid/cb' },
    exchangeIds: ['sh-redir-ctrl', 'sh-redir-probe'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'Redirected to external off-origin host controlled by next parameter',
  }
  const redirectTranscript = signTranscript({
    entries: [
      makeEntry('sh-redir-ctrl', makeStep({
        id: 'sh-redir-ctrl', arm: 'control', method: 'GET', status: 302,
        route: '/login', pathAndQuery: '/login?next=/dashboard',
        responseHeaders: { location: '/dashboard' },
      }), { timestampMs: 1000, actorPersona: 'member_alpha' }),
      makeEntry('sh-redir-probe', makeStep({
        id: 'sh-redir-probe', arm: 'probe', method: 'GET', status: 302,
        route: '/login', pathAndQuery: '/login?next=https://external.example.invalid/cb',
        responseHeaders: { location: 'https://external.example.invalid/cb' },
      }), { timestampMs: 1200, actorPersona: 'member_alpha' }),
    ],
  })

  // 4. Conserved balance race
  const raceProof: ProofReceipt = {
    vulnClass: 'race_double_spend',
    target: { origin: ORIGIN_API, method: 'POST', pathAndQuery: '/api/credits/redeem' },
    exchangeIds: ['sh-race-base', 'sh-race-b1', 'sh-race-b2', 'sh-race-post', 'sh-race-serial'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'Concurrent burst redeemed 2x 50 credits while balance only debited 50',
    conservedBalance: { balanceField: 'balance', unitDebit: 50 },
  }
  const raceTranscript = signTranscript({
    entries: [
      makeEntry('sh-race-base', makeStep({
        id: 'sh-race-base', arm: 'setup', method: 'GET', status: 200,
        route: '/api/credits', pathAndQuery: '/api/credits', json: { balance: 100 },
      }), { timestampMs: 1000, actorPersona: 'member_alpha', evidenceRole: 'baseline_read' }),
      makeEntry('sh-race-b1', makeStep({
        id: 'sh-race-b1', arm: 'probe', method: 'POST', status: 200,
        route: '/api/credits/redeem', pathAndQuery: '/api/credits/redeem',
        requestJson: { amount: 50 }, json: { ok: true, redeemed: 50 },
      }), { timestampMs: 1100, actorPersona: 'member_alpha', evidenceRole: 'burst_1' }),
      makeEntry('sh-race-b2', makeStep({
        id: 'sh-race-b2', arm: 'probe', method: 'POST', status: 200,
        route: '/api/credits/redeem', pathAndQuery: '/api/credits/redeem',
        requestJson: { amount: 50 }, json: { ok: true, redeemed: 50 },
      }), { timestampMs: 1101, actorPersona: 'member_alpha', evidenceRole: 'burst_2' }),
      makeEntry('sh-race-post', makeStep({
        id: 'sh-race-post', arm: 'control', method: 'GET', status: 200,
        route: '/api/credits', pathAndQuery: '/api/credits', json: { balance: 50 },
      }), { timestampMs: 1300, actorPersona: 'member_alpha', evidenceRole: 'post_read' }),
      makeEntry('sh-race-serial', makeStep({
        id: 'sh-race-serial', arm: 'control', method: 'POST', status: 409,
        route: '/api/credits/redeem', pathAndQuery: '/api/credits/redeem',
        requestJson: { amount: 50 }, json: { error: 'already_redeemed' },
      }), { timestampMs: 1500, actorPersona: 'member_alpha', evidenceRole: 'serial_control' }),
    ],
  })

  return [
    { name: 'single:bola', proof: bolaProof, transcript: bolaTranscript },
    { name: 'single:oob_ssrf', proof: oobProof, transcript: oobTranscript },
    { name: 'single:open_redirect', proof: redirectProof, transcript: redirectTranscript },
    { name: 'single:conserved_balance', proof: raceProof, transcript: raceTranscript },
  ]
}

function buildAllBaselines(): BaselineFixture[] {
  return [
    buildValueBindingBaseline(),
    buildDerivedCryptoBaseline(),
    buildStateTransitionBaseline(),
    buildAsyncPivotBaseline('poll_convergence'),
    buildAsyncPivotBaseline('oob_relay'),
    buildAsyncPivotBaseline('browser_trace'),
    buildAsyncPivotBaseline('async_job'),
    buildDualTenantAbacBaseline(),
    buildTemporalRevocationBaseline(),
    buildEconomicConservationBaseline(),
    buildCryptoScopeReplayBaseline(),
    buildParserCacheBaseline(),
    buildCrossSurfacePivotBaseline(),
  ]
}

// ============================================================================
// 0. Anti-Contamination Self-Check
// ============================================================================

test('Seam 3 fuzz suite itself contains zero v8 benchmark literals', () => {
  const selfPath = fileURLToPath(import.meta.url)
  const content = readFileSync(selfPath, 'utf8')
  const hits = scanTextForContamination('tests/v8-seam3-receipt-fuzz.test.ts', content)
  assert.deepEqual(hits, [], `Contamination found in fuzz suite: ${JSON.stringify(hits)}`)
})

// ============================================================================
// 1. Clean Valid Baselines (All 4 Edges + All 6 Oracle Families + Single-Hop)
// ============================================================================

test('Baselines: all 4 causal edge kinds, all 6 V8_ORACLE_FAMILIES, and single-hop ProofReceipts PASS cleanly', () => {
  const baselines = buildAllBaselines()
  const coveredEdges = new Set<string>()
  const coveredFamilies = new Set<string>()

  for (const base of baselines) {
    const res = verifyCompositeReceipt(base.receipt, base.transcript, base.options)
    assert.equal(res.confirmed, true, `Baseline "${base.name}" failed: ${res.reason}`)
    assertNoSigningKeyLeak(res)
    for (const edge of res.verifiedEdges) {
      assert.equal(edge.verified, true)
      coveredEdges.add(edge.kind)
    }
    if (res.terminalOracleFamily) coveredFamilies.add(res.terminalOracleFamily)
  }

  for (const kind of CAUSAL_EDGE_KINDS) {
    assert.ok(coveredEdges.has(kind), `Missing baseline coverage for causal edge kind "${kind}"`)
  }
  for (const fam of ALL_V8_FAMILIES) {
    assert.ok(coveredFamilies.has(fam), `Missing baseline coverage for V8 oracle family "${fam}"`)
  }

  for (const sh of buildSingleHopProofReceipts()) {
    const v7 = verifyReceipt(sh.proof, sh.transcript)
    assert.equal(v7.confirmed, true, `Single-hop v7 baseline "${sh.name}" failed: ${v7.reason}`)
    const wrapped = singleReceiptToComposite(sh.proof)
    const v8 = verifyCompositeReceipt(wrapped, sh.transcript, {
      attackerPersonas: ['member_alpha'],
      signingKey: SIGNING_KEY,
    })
    assert.equal(v8.confirmed, true, `Single-hop v8 bridge "${sh.name}" failed: ${v8.reason}`)
    assertNoSigningKeyLeak(v8)
  }
})

// ============================================================================
// 2. Deterministic Adversarial Mutation Catalog (18+ Systematic Mutations)
// ============================================================================

test('M01: Reversing or swapping hop timestamps (t_from > t_to) fails closed across all 4 edges & v8 oracles', () => {
  // 1a. value_binding
  {
    const b = buildValueBindingBaseline()
    const t = deepClone(b.transcript)
    t.entries![1]!.timestampMs = 2500
    t.entries![2]!.timestampMs = 1500
    const res = verifyCompositeReceipt(b.receipt, signTranscript(t), b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
    assert.match(res.reason, /monotonic/i)
  }
  // 1b. derived_crypto_binding
  {
    const b = buildDerivedCryptoBaseline()
    const t = deepClone(b.transcript)
    t.entries![1]!.timestampMs = 2000 // t_source > t_derive (1300)
    const res = verifyCompositeReceipt(b.receipt, signTranscript(t), b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
  }
  // 1c. state_transition_binding
  {
    const b = buildStateTransitionBaseline()
    const t = deepClone(b.transcript)
    t.entries![1]!.timestampMs = 2200 // hop1 > hop2 (1600)
    t.entries![2]!.timestampMs = 1200
    const res = verifyCompositeReceipt(b.receipt, signTranscript(t), b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
    assert.match(res.reason, /monotonic/i)
  }
  // 1d. async_pivot_binding across all 4 channels
  for (const ch of ['poll_convergence', 'oob_relay', 'browser_trace', 'async_job'] as const) {
    const b = buildAsyncPivotBaseline(ch)
    const t = deepClone(b.transcript)
    t.entries![0]!.timestampMs = 5000 // trigger AFTER observation
    const res = verifyCompositeReceipt(b.receipt, signTranscript(t), b.options)
    assert.equal(res.confirmed, false, `async_pivot_binding (${ch}) allowed t_trigger > t_observed`)
    assert.equal(res.failedStage, 'edge_binding')
  }
  // 1e. V8 oracle temporal inversions (dual_tenant_abac, temporal_revocation, economic_conservation, cryptographic_scope_replay, parser_cache_differential)
  {
    const dt = buildDualTenantAbacBaseline()
    const t = deepClone(dt.transcript)
    t.entries![1]!.timestampMs = 2500 // transfer AFTER readback (1600)
    assert.equal(verifyCompositeReceipt(dt.receipt, signTranscript(t), dt.options).confirmed, false)
  }
  {
    const tr = buildTemporalRevocationBaseline()
    const t = deepClone(tr.transcript)
    t.entries!.find(e => e.exchangeId === 'ex-tr-denied')!.timestampMs = 1100 // primaryDenied BEFORE revocation (1200)
    assert.equal(verifyCompositeReceipt(tr.receipt, signTranscript(t), tr.options).confirmed, false)
  }
  {
    const ec = buildEconomicConservationBaseline()
    const t = deepClone(ec.transcript)
    t.entries![3]!.timestampMs = 1200 // finalReadback BEFORE actions (1400)
    assert.equal(verifyCompositeReceipt(ec.receipt, signTranscript(t), ec.options).confirmed, false)
  }
  {
    const cs = buildCryptoScopeReplayBaseline()
    const t = deepClone(cs.transcript)
    t.entries![2]!.timestampMs = 1100 // replay BEFORE issuance (1200)
    assert.equal(verifyCompositeReceipt(cs.receipt, signTranscript(t), cs.options).confirmed, false)
  }
  {
    const pc = buildParserCacheBaseline()
    const t = deepClone(pc.transcript)
    t.entries![2]!.timestampMs = 1100 // attacker probe BEFORE victim prime (1200)
    assert.equal(verifyCompositeReceipt(pc.receipt, signTranscript(t), pc.options).confirmed, false)
  }
})

test('M02–M04: State-transition ablation mutations (dropped, 200 OK, 500 error, reused hop, dirty post-mutation) all fail closed', () => {
  const base = buildStateTransitionBaseline()

  // M02a: Drop ablationExchangeIds completely -> schema rejection
  {
    const r = deepClone(base.receipt)
    ;(r.causalEdges[0] as { ablationExchangeIds: string[] }).ablationExchangeIds = []
    const res = verifyCompositeReceipt(r, base.transcript, base.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'schema')
  }
  // M02b: Cite nonexistent ablation exchange -> transcript_integrity rejection
  {
    const r = deepClone(base.receipt)
    ;(r.causalEdges[0] as { ablationExchangeIds: string[] }).ablationExchangeIds = ['ex-ghost-ablation']
    const res = verifyCompositeReceipt(r, base.transcript, base.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'transcript_integrity')
  }
  // M02c: Reuse hop exchange as ablation -> edge_binding rejection
  {
    const r = deepClone(base.receipt)
    ;(r.causalEdges[0] as { ablationExchangeIds: string[] }).ablationExchangeIds = ['ex-st-2']
    const res = verifyCompositeReceipt(r, base.transcript, base.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
  }
  // M03: Ablation succeeds (200 / 201 / 204) or errors (500 / 502) -> edge_binding rejection
  for (const status of [200, 201, 204, 500, 502]) {
    const t = deepClone(base.transcript)
    t.entries![0]!.step.status = status
    const res = verifyCompositeReceipt(base.receipt, signTranscript(t), base.options)
    assert.equal(res.confirmed, false, `Ablation status=${status} should have been rejected`)
    assert.equal(res.failedStage, 'edge_binding')
  }
  // M04a: Dirty post-mutation ablation (`cleanSession: false`) -> edge_binding rejection
  {
    const t = deepClone(base.transcript)
    t.entries![0]!.cleanSession = false
    t.entries![0]!.timestampMs = 1400
    const res = verifyCompositeReceipt(base.receipt, signTranscript(t), base.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
    assert.match(res.reason, /cleanSession=false/i)
  }
  // M04b: Unlabeled post-mutation ablation (`arm: 'probe'`, no `replayAttempt`, `timestampMs > t_from`) -> edge_binding rejection
  {
    const t = deepClone(base.transcript)
    t.entries![0]!.step.arm = 'probe'
    delete t.entries![0]!.replayAttempt
    t.entries![0]!.timestampMs = 1500
    const res = verifyCompositeReceipt(base.receipt, signTranscript(t), base.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
  }
  // M04c: Ablation actor mismatch (anon masquerading for member_alpha) -> edge_binding rejection
  {
    const t = deepClone(base.transcript)
    t.entries![0]!.actorPersona = 'anon'
    t.entries![0]!.step.actor.handle = 'anon'
    const res = verifyCompositeReceipt(base.receipt, signTranscript(t), base.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
  }
})

test('M05: Replacing terminal response with intermediate job/export/signed-URL/draft/queued stub fails closed', () => {
  const stubs: Array<{ label: string; status: number; json?: unknown; body?: string }> = [
    { label: 'queued_job', status: 202, json: { jobId: 'job-101', status: 'queued' } },
    { label: 'pending_export', status: 200, json: { exportId: 'exp-55', state: 'pending' } },
    { label: 'signed_url_handle', status: 200, json: { signedUrl: 'https://cdn.example.test/download/abc123', expiresIn: 300 } },
    { label: 'download_path_stub', status: 200, json: { downloadUrl: '/api/exports/99/download', status: 'ready' } },
    { label: 'draft_envelope', status: 200, json: { job: { job_id: 'j-7', status: 'created', createdAt: '2026-01-01T00:00:00Z' } } },
    { label: 'bare_queued_text', status: 202, body: 'queued' },
    { label: 'cache_ack_stub', status: 200, json: { ok: true, cacheStatus: 'primed', cacheKey: 'k-1' } },
  ]

  for (const stub of stubs) {
    // Against value_binding cross_tenant_read baseline
    const vb = buildValueBindingBaseline()
    const t1 = deepClone(vb.transcript)
    const term = t1.entries![2]!
    term.step.status = stub.status
    term.step.json = stub.json
    term.step.body = stub.body
    const r1 = verifyCompositeReceipt(vb.receipt, signTranscript(t1), vb.options)
    assert.equal(r1.confirmed, false, `Stub "${stub.label}" confirmed on value_binding baseline`)
    assert.equal(r1.failedStage, 'terminal_impact')
    assert.equal(r1.rejectedBy, 'terminal_impact_unproven')

    // Against dual_tenant_abac baseline (postTransferReadback replaced with stub)
    const dt = buildDualTenantAbacBaseline()
    const t2 = deepClone(dt.transcript)
    t2.entries![2]!.step.status = stub.status
    t2.entries![2]!.step.json = stub.json
    t2.entries![2]!.step.body = stub.body
    const r2 = verifyCompositeReceipt(dt.receipt, signTranscript(t2), dt.options)
    assert.equal(r2.confirmed, false, `Stub "${stub.label}" confirmed on dual_tenant_abac baseline`)
    assert.equal(r2.failedStage, 'terminal_impact')
  }
})

test('M06: Forged cryptoAttestations (digest, source cap, derived cap, alg, timestamps, missing) all fail closed', () => {
  const base = buildDerivedCryptoBaseline()

  // 6a. Invalid / non-hex artifactDigest
  for (const badDigest of ['', 'not-a-sha256', 'z'.repeat(64), 'a'.repeat(63)]) {
    const t = deepClone(base.transcript)
    t.entries![2]!.cryptoAttestations![0]!.artifactDigest = badDigest
    const res = verifyCompositeReceipt(base.receipt, signTranscript(t), base.options)
    assert.equal(res.confirmed, false, `Invalid artifactDigest "${badDigest}" should fail`)
    assert.equal(res.failedStage, 'edge_binding')
  }
  // 6b. Forged derivedFromCapabilityId
  {
    const t = deepClone(base.transcript)
    t.entries![2]!.cryptoAttestations![0]!.derivedFromCapabilityId = 'cap:hop_1:wrong_key'
    const res = verifyCompositeReceipt(base.receipt, signTranscript(t), base.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
  }
  // 6c. Mismatched derivedCapabilityId
  {
    const t = deepClone(base.transcript)
    t.entries![2]!.cryptoAttestations![0]!.derivedCapabilityId = 'cap:hop_2:other_jwt'
    const res = verifyCompositeReceipt(base.receipt, signTranscript(t), base.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
  }
  // 6d. Wrong alg
  {
    const t = deepClone(base.transcript)
    t.entries![2]!.cryptoAttestations![0]!.alg = 'HS512'
    const res = verifyCompositeReceipt(base.receipt, signTranscript(t), base.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
  }
  // 6e. t_derive < t_source (999 < 1000)
  {
    const t = deepClone(base.transcript)
    t.entries![2]!.cryptoAttestations![0]!.timestampMs = 999
    const res = verifyCompositeReceipt(base.receipt, signTranscript(t), base.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
  }
  // 6f. t_derive > t_request (1501 > 1500)
  {
    const t = deepClone(base.transcript)
    t.entries![2]!.cryptoAttestations![0]!.timestampMs = 1501
    const res = verifyCompositeReceipt(base.receipt, signTranscript(t), base.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
  }
  // 6g. Missing cryptoAttestations
  {
    const t = deepClone(base.transcript)
    t.entries![2]!.cryptoAttestations = []
    const res = verifyCompositeReceipt(base.receipt, signTranscript(t), base.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
  }
})

test('M07–M08: Forbidden shortcut persona swap and cross-tenant probe-arm collusion fail closed', () => {
  // M07a: Forbidden shortcut persona on root hop
  {
    const b = buildValueBindingBaseline()
    const t = deepClone(b.transcript)
    t.entries![1]!.actorPersona = 'admin_beta'
    t.entries![1]!.step.actor = { handle: 'admin_beta', role: 'admin', tenant: 'org-beta', auth: 'bearer', sameSite: null }
    const res = verifyCompositeReceipt(b.receipt, signTranscript(t), b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'attacker_provenance')
  }
  // M07b: Forbidden shortcut persona on downstream hop
  {
    const b = buildValueBindingBaseline()
    const t = deepClone(b.transcript)
    t.entries![2]!.actorPersona = 'owner_beta'
    const res = verifyCompositeReceipt(b.receipt, signTranscript(t), b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'attacker_provenance')
  }
  // M07c: Owner role when attackerPersonas list is omitted
  {
    const b = buildValueBindingBaseline()
    const t = deepClone(b.transcript)
    t.entries![1]!.actorRoleLabel = 'owner (org-beta)'
    t.entries![1]!.step.actor.role = 'owner'
    const res = verifyCompositeReceipt(b.receipt, signTranscript(t), { signingKey: SIGNING_KEY })
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'attacker_provenance')
  }
  // M08: Cross-tenant probe-arm collusion (hop 1 = org-alpha, hop 2 = org-beta both allowed)
  {
    const b = buildValueBindingBaseline()
    const t = deepClone(b.transcript)
    t.entries![2]!.actorPersona = 'member_beta'
    t.entries![2]!.actorRoleLabel = 'member (org-beta)'
    t.entries![2]!.step.actor = { handle: 'member_beta', role: 'member', tenant: 'org-beta', auth: 'bearer', sameSite: null }
    const res = verifyCompositeReceipt(b.receipt, signTranscript(t), {
      attackerPersonas: ['member_alpha', 'member_beta'],
      signingKey: SIGNING_KEY,
    })
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'attacker_provenance')
    assert.match(res.reason, /cross-tenant probe-arm/i)
  }
})

test('M09: Unbound/unused value_binding handle or mismatched valueDigest fails closed', () => {
  const b = buildValueBindingBaseline()
  // 9a. Handle not emitted in hop_1
  {
    const t = deepClone(b.transcript)
    t.entries![1]!.emittedCapabilities = []
    const res = verifyCompositeReceipt(b.receipt, signTranscript(t), b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
  }
  // 9b. Handle not consumed in hop_2
  {
    const t = deepClone(b.transcript)
    t.entries![2]!.consumedCapabilities = []
    const res = verifyCompositeReceipt(b.receipt, signTranscript(t), b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
  }
  // 9c. Mismatched valueDigest
  {
    const r = deepClone(b.receipt)
    ;(r.causalEdges[0] as { valueDigest?: string }).valueDigest = sha256Hex('completely-different-value')
    const res = verifyCompositeReceipt(r, b.transcript, b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'edge_binding')
  }
  // 9d. Neither capabilityHandle nor valueDigest -> schema failure
  {
    const r = deepClone(b.receipt)
    delete (r.causalEdges[0] as { capabilityHandle?: string }).capabilityHandle
    delete (r.causalEdges[0] as { valueDigest?: string }).valueDigest
    const res = verifyCompositeReceipt(r, b.transcript, b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'schema')
  }
})

test('M10–M11: Disconnected DAG (orphan hop), cycles, self-loop, duplicate hop/edge, empty/oversized hops fail closed', () => {
  const b = buildValueBindingBaseline()

  // M10: Orphan hop not reaching terminalHopId
  {
    const r = deepClone(b.receipt)
    r.hops.push({
      hopId: 'hop_orphan', surface: 'http',
      target: { origin: ORIGIN_API, pathAndQuery: '/api/unused' },
      exchangeIds: ['ex-vb-1'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Orphan hop', producedCapabilities: [], consumedCapabilities: [],
    })
    const res = verifyCompositeReceipt(r, b.transcript, b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'dag_topology')
    assert.match(res.reason, /does not reach terminalHopId/i)
  }
  // M11a: Cycle hop_1 -> hop_2 -> hop_1
  {
    const r = deepClone(b.receipt)
    r.causalEdges.push({ kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_1', capabilityHandle: 'cap:hop_1:delegated_tok' })
    const res = verifyCompositeReceipt(r, b.transcript, b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'dag_topology')
    assert.match(res.reason, /cycle/i)
  }
  // M11b: Self-loop hop_1 -> hop_1
  {
    const r = deepClone(b.receipt)
    r.causalEdges.push({ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_1', capabilityHandle: 'cap:hop_1:delegated_tok' })
    const res = verifyCompositeReceipt(r, b.transcript, b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'dag_topology')
    assert.match(res.reason, /self-loop/i)
  }
  // M11c: Duplicate hop IDs
  {
    const r = deepClone(b.receipt)
    r.hops.push({ ...r.hops[0]! })
    const res = verifyCompositeReceipt(r, b.transcript, b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'dag_topology')
    assert.match(res.reason, /Duplicate hopId/i)
  }
  // M11d: Duplicate causal edge
  {
    const r = deepClone(b.receipt)
    r.causalEdges.push({ ...r.causalEdges[0]! })
    const res = verifyCompositeReceipt(r, b.transcript, b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'dag_topology')
    assert.match(res.reason, /Duplicate causal edge/i)
  }
  // M11e: Empty hops
  {
    const r = deepClone(b.receipt)
    r.hops = []
    const res = verifyCompositeReceipt(r, b.transcript, b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'schema')
  }
  // M11f: 9 hops (exceeds max 8)
  {
    const r = deepClone(b.receipt)
    r.hops = Array.from({ length: 9 }, (_, i) => ({
      hopId: `hop_${i + 1}`, surface: 'http' as const,
      target: { origin: ORIGIN_API, pathAndQuery: `/api/h/${i + 1}` },
      exchangeIds: ['ex-vb-1'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: `Hop ${i + 1}`, producedCapabilities: [], consumedCapabilities: [],
    }))
    const res = verifyCompositeReceipt(r, b.transcript, b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'schema')
  }
  // M11g: terminalHopId absent from hops
  {
    const r = deepClone(b.receipt)
    r.terminalImpact.terminalHopId = 'hop_nonexistent'
    const res = verifyCompositeReceipt(r, b.transcript, b.options)
    assert.equal(res.confirmed, false)
    assert.equal(res.failedStage, 'dag_topology')
  }
})

test('M12–M14: Tampered host signatures, TranscriptStore tamper, and Mode-B (one_shot_transcript) abuse fail closed', () => {
  // M12: Host record signature tamper (flip 1 nibble, strip sig, post-sign body mutation, wrong signing key)
  {
    const b = buildValueBindingBaseline()
    const t1 = deepClone(b.transcript)
    const orig = t1.entries![1]!.hostSignature!
    t1.entries![1]!.hostSignature = (orig[0] === 'a' ? 'b' : 'a') + orig.slice(1)
    assert.equal(verifyCompositeReceipt(b.receipt, t1, b.options).failedStage, 'transcript_integrity')

    const t2 = deepClone(b.transcript)
    delete t2.entries![2]!.hostSignature
    assert.equal(verifyCompositeReceipt(b.receipt, t2, b.options).failedStage, 'transcript_integrity')

    const t3 = deepClone(b.transcript)
    t3.entries![2]!.step.status = 201 // mutated after signing
    assert.equal(verifyCompositeReceipt(b.receipt, t3, b.options).failedStage, 'transcript_integrity')

    assert.equal(verifyCompositeReceipt(b.receipt, b.transcript, { ...b.options, signingKey: 'wrong-key-value' }).failedStage, 'transcript_integrity')
  }

  // M12b: Tampered OOB / browser trace / poll signatures
  for (const ch of ['oob_relay', 'browser_trace', 'poll_convergence'] as const) {
    const b = buildAsyncPivotBaseline(ch)
    const t = deepClone(b.transcript)
    if (ch === 'oob_relay') t.oobEvents![0]!.hostSignature = '0'.repeat(64)
    if (ch === 'browser_trace') t.browserTraces![0]!.hostSignature = '0'.repeat(64)
    if (ch === 'poll_convergence') t.asyncPollRecords![0]!.hostSignature = '0'.repeat(64)
    const res = verifyCompositeReceipt(b.receipt, t, b.options)
    assert.equal(res.confirmed, false, `Tampered ${ch} signature should fail`)
    assert.equal(res.failedStage, 'transcript_integrity')
  }

  // M13: TranscriptStore signature & digest tamper detection + forged composite_receipt claim
  {
    const store = new TranscriptStore()
    const r1 = store.record({
      op: 'http', startedAt: 1000, durationMs: 10,
      request: { origin: ORIGIN_API, method: 'GET', pathAndQuery: '/api/orders/1', headers: {}, bodyBytes: 0, bodySha256: sha256Hex(''), nonce: 'n1' },
      response: { status: 200, headers: {}, bodyBytes: 12, bodySha256: sha256Hex('{"ok":true}'), mediaType: 'application/json' },
      body: '{"ok":true}',
    })
    const comp = store.recordCompositeVerification({
      chainId: 'chain-1', terminalVulnClass: 'business_logic', replayMode: 'fresh_clean_replay',
      hopCount: 2, confirmed: false, verifiedEdgeCount: 1, reason: 'failed', failedStage: 'terminal_impact',
      rejectedBy: 'terminal_impact_unproven', missingEvidence: ['clean_denied_control'], exchangeIds: [r1.exchangeId],
      terminalExchangeId: r1.exchangeId, route: '/api/orders/1',
    })
    const digestBefore = store.digest()
    assert.equal(store.verifySignatures(), true)

    // Forged composite_receipt claim referencing unconfirmed host record fails
    const evalRejected = evaluateClaims(store, [{
      kind: 'composite_receipt', verificationId: comp.verificationId,
      chainId: 'chain-1', terminalVulnClass: 'business_logic', exchangeIds: [r1.exchangeId],
    }])
    assert.equal(evalRejected.passed, false)

    // Forged composite_receipt claim with fabricated verificationId fails
    const evalGhost = evaluateClaims(store, [{
      kind: 'composite_receipt', verificationId: 'gc-forged-id',
      chainId: 'chain-1', terminalVulnClass: 'business_logic', exchangeIds: [r1.exchangeId],
    }])
    assert.equal(evalGhost.passed, false)

    // Mutate composite verification record in-place (confirmed: false -> true)
    ;(comp as { confirmed: boolean }).confirmed = true
    assert.equal(store.verifySignatures(), false, 'Tampering TranscriptCompositeVerification must break verifySignatures()')

    // Mutate HTTP record status in-place
    ;(comp as { confirmed: boolean }).confirmed = false
    assert.equal(store.verifySignatures(), true)
    ;(r1.response as { status: number }).status = 403
    assert.equal(store.verifySignatures(), false, 'Tampering VerifyTranscriptRecord must break verifySignatures()')
    assert.equal(store.digest(), digestBefore) // digest hashes signatures; verifySignatures catches payload tamper
  }

  // M14: Mode-B (`replayMode: 'one_shot_transcript'`) abuse
  {
    const b = buildValueBindingBaseline()
    const makeModeB = (modeAStatus: number, modeABody: string, extraReceipt: Partial<CompositeProofReceipt> = {}) => {
      const t = deepClone(b.transcript)
      t.entries = [
        ...(t.entries ?? []),
        makeEntry('ex-mode-a-fail', makeStep({
          id: 'ex-mode-a-fail', arm: 'probe', method: 'GET', status: modeAStatus,
          route: '/api/records/rec-900', pathAndQuery: '/api/records/rec-900', body: modeABody,
        }), { timestampMs: 2200, actorPersona: 'member_alpha', cleanSession: true, replayAttempt: 'mode_a' }),
        makeEntry('ex-post-rb', makeStep({
          id: 'ex-post-rb', arm: 'control', method: 'GET', status: 200,
          route: '/api/records/rec-900', pathAndQuery: '/api/records/rec-900',
          json: { id: 'rec-900', tenantId: 'org-beta', balanceCents: 450000 },
          evidenceRole: 'post_chain_readback',
        }), { timestampMs: 2400, actorPersona: 'member_alpha' }),
      ]
      const r: CompositeProofReceipt = {
        ...deepClone(b.receipt),
        replayMode: 'one_shot_transcript',
        terminalImpact: {
          ...deepClone(b.receipt.terminalImpact),
          modeAFailureExchangeId: 'ex-mode-a-fail',
          postChainReadbackExchangeIds: ['ex-post-rb'],
        },
        ...extraReceipt,
      }
      return { r, t: signTranscript(t) }
    }

    // Valid Mode B with 409 passes outside benchmarkMode
    const valid = makeModeB(409, '{"error":"already_consumed"}')
    assert.equal(verifyCompositeReceipt(valid.r, valid.t, b.options).confirmed, true)

    // Forbidden in benchmarkMode (both option and receipt flag)
    assert.equal(verifyCompositeReceipt(valid.r, valid.t, { ...b.options, benchmarkMode: true }).failedStage, 'replay_mode')
    const bmReceipt = makeModeB(409, '{"error":"already_consumed"}', { benchmarkMode: true })
    assert.equal(verifyCompositeReceipt(bmReceipt.r, bmReceipt.t, b.options).failedStage, 'replay_mode')

    // Mode-A returned 403 / 500 / 200 -> rejected
    for (const badSt of [200, 403, 500]) {
      const bad = makeModeB(badSt, '{"error":"denied"}')
      assert.equal(verifyCompositeReceipt(bad.r, bad.t, b.options).failedStage, 'replay_mode')
    }

    // Missing modeAFailureExchangeId -> rejected
    const noModeA = deepClone(valid.r)
    delete noModeA.terminalImpact.modeAFailureExchangeId
    assert.equal(verifyCompositeReceipt(noModeA, valid.t, b.options).failedStage, 'replay_mode')

    // Missing post-chain readback -> rejected
    const noRb = deepClone(valid.r)
    noRb.terminalImpact.postChainReadbackExchangeIds = []
    assert.equal(verifyCompositeReceipt(noRb, valid.t, b.options).failedStage, 'replay_mode')

    // Post-chain readback is a job stub -> rejected
    const stubT = deepClone(valid.t)
    const rbEntry = stubT.entries!.find(e => e.exchangeId === 'ex-post-rb')!
    rbEntry.step.json = { jobId: 'j-1', status: 'queued' }
    assert.equal(verifyCompositeReceipt(valid.r, signTranscript(stubT), b.options).failedStage, 'replay_mode')
  }
})

test('M15–M16: V8 oracle family invariant mutations & single-hop ProofReceipt mutations fail closed', () => {
  // Dual-tenant ABAC: actor already authorized in source tenant
  {
    const b = buildDualTenantAbacBaseline()
    const r = deepClone(b.receipt)
    ;(r.terminalImpact.oracleInput as { actor: { rolesByTenant: Record<string, string> } }).actor.rolesByTenant['org-beta'] = 'admin'
    assert.equal(verifyCompositeReceipt(r, b.transcript, b.options).confirmed, false)
  }
  // Temporal revocation: primary surface returned 200 (not revoked)
  {
    const b = buildTemporalRevocationBaseline()
    const t = deepClone(b.transcript)
    t.entries!.find(e => e.exchangeId === 'ex-tr-denied')!.step.status = 200
    assert.equal(verifyCompositeReceipt(b.receipt, signTranscript(t), b.options).confirmed, false)
  }
  // Economic conservation: refund conserved (refunded <= paid)
  {
    const b = buildEconomicConservationBaseline()
    const r = deepClone(b.receipt)
    ;(r.terminalImpact.oracleInput as { refundedAmounts: number[] }).refundedAmounts = [50, 50]
    assert.equal(verifyCompositeReceipt(r, b.transcript, b.options).confirmed, false)
  }
  // Cryptographic scope replay: tampered signature control accepted (200 decoy)
  {
    const b = buildCryptoScopeReplayBaseline()
    const t = deepClone(b.transcript)
    t.entries![0]!.step.status = 200
    assert.equal(verifyCompositeReceipt(b.receipt, signTranscript(t), b.options).confirmed, false)
  }
  // Parser/cache differential: missing cache hit evidence & attacker digest mismatch
  {
    const b = buildParserCacheBaseline()
    const r = deepClone(b.receipt)
    ;(r.terminalImpact.oracleInput as { cacheHitObserved: boolean }).cacheHitObserved = false
    const t = deepClone(b.transcript)
    t.entries![2]!.step.responseHeaders = {}
    assert.equal(verifyCompositeReceipt(r, signTranscript(t), b.options).confirmed, false)
  }
  // Cross-surface pivot: collapsing both hops onto single surface fails closed
  {
    const b = buildCrossSurfacePivotBaseline()
    const r = deepClone(b.receipt)
    r.hops[0]!.surface = 'http'
    assert.equal(verifyCompositeReceipt(r, b.transcript, b.options).confirmed, false)
  }
  // Single-hop ProofReceipt mutations
  const singles = buildSingleHopProofReceipts()
  // OOB callback before injection
  {
    const oob = deepClone(singles[1]!)
    oob.transcript.oobEvents![0]!.receivedAtMs = 500
    assert.equal(verifyReceipt(oob.proof, oob.transcript).confirmed, false)
    assert.equal(verifyCompositeReceipt(singleReceiptToComposite(oob.proof), signTranscript(oob.transcript), { signingKey: SIGNING_KEY }).confirmed, false)
  }
  // Open redirect staying on same origin
  {
    const redir = deepClone(singles[2]!)
    redir.transcript.entries![1]!.step.responseHeaders = { location: `${ORIGIN_API}/settings` }
    assert.equal(verifyReceipt(redir.proof, redir.transcript).confirmed, false)
  }
  // Race with conserved balance (full 100 debited -> balance 0)
  {
    const race = deepClone(singles[3]!)
    race.transcript.entries![3]!.step.json = { balance: 0 }
    assert.equal(verifyReceipt(race.proof, race.transcript).confirmed, false)
  }
})

// ============================================================================
// 3. Dual-Replay Divergence Fuzzing (`verifyScript` -> `transcript_mismatch`)
// ============================================================================

test('M17: Dual-replay Run 1 vs Run 2 divergence on route, method, claim kind, oracle family, title, nonce, or signature fails closed', async () => {
  interface AttemptSpec {
    method: string
    route: string
    claimKind: 'composite_receipt' | 'boundary'
    oracleFamily: V8OracleFamily
    title: string
    tamperSig?: boolean
    echoWrongNonce?: boolean
  }

  const baseSpec: AttemptSpec = {
    method: 'POST',
    route: '/api/v1/transfers/100',
    claimKind: 'composite_receipt',
    oracleFamily: 'dual_tenant_abac',
    title: 'Cross-tenant transfer access control differential',
  }

  const runDual = async (spec1: AttemptSpec, spec2: AttemptSpec) => verifyScript({
    candidate: { name: 'dual-fuzz', runtime: 'ts', code: '' },
    doubleReplay: true,
    openAttempt: async ({ attempt, nonce }) => {
      const spec = attempt === 1 ? spec1 : spec2
      const store = new TranscriptStore()
      const ctrl = store.record({
        op: 'http', startedAt: Date.now(), durationMs: 5,
        request: {
          origin: ORIGIN_API, method: spec.method, pathAndQuery: spec.route,
          headers: {}, bodyBytes: 0, bodySha256: sha256Hex(''),
          personaHandle: 'member_alpha', sessionRole: 'control', nonce,
        },
        response: { status: 403, headers: {}, bodyBytes: 18, bodySha256: sha256Hex('{"error":"denied"}'), mediaType: 'application/json' },
        body: '{"error":"denied"}',
      })
      const ex = store.record({
        op: 'http', startedAt: Date.now() + 10, durationMs: 8,
        request: {
          origin: ORIGIN_API, method: spec.method, pathAndQuery: spec.route,
          headers: {}, bodyBytes: 0, bodySha256: sha256Hex(''),
          personaHandle: 'member_alpha', sessionRole: 'probe', nonce,
        },
        response: { status: 200, headers: {}, bodyBytes: 24, bodySha256: sha256Hex('{"transferred":true}'), mediaType: 'application/json' },
        body: '{"transferred":true}',
      })
      const compRec = store.recordCompositeVerification({
        chainId: 'chain-dual-fuzz',
        terminalVulnClass: spec.oracleFamily,
        replayMode: 'fresh_clean_replay',
        hopCount: 2,
        confirmed: true,
        verifiedEdgeCount: 1,
        reason: 'CompositeProofReceipt confirmed',
        rejectedBy: null,
        missingEvidence: [],
        exchangeIds: [ctrl.exchangeId, ex.exchangeId],
        terminalExchangeId: ex.exchangeId,
        route: spec.route,
      })
      const claim: VerifyClaim = spec.claimKind === 'composite_receipt'
        ? {
            kind: 'composite_receipt',
            verificationId: compRec.verificationId,
            chainId: 'chain-dual-fuzz',
            terminalVulnClass: spec.oracleFamily,
            route: spec.route,
            exchangeIds: [ctrl.exchangeId, ex.exchangeId],
            terminalExchangeId: ex.exchangeId,
            replayMode: 'fresh_clean_replay',
            hopCount: 2,
            compositeReceipt: {
              chainId: 'chain-dual-fuzz',
              terminalVulnClass: spec.oracleFamily,
              hops: [{ hopId: 'hop_1', exchangeIds: [ex.exchangeId] }],
              causalEdges: [{ kind: 'value_binding' }],
              terminalImpact: { terminalHopId: 'hop_1', oracleFamily: spec.oracleFamily },
            },
          }
        : {
            kind: 'boundary',
            boundaryClass: 'access',
            controlExchangeId: ctrl.exchangeId,
            probeExchangeId: ex.exchangeId,
            expectControlDenied: true,
          }

      if (spec.tamperSig) {
        ;(ex.response as { status: number }).status = 201
      }

      return {
        nonce,
        transcript: store,
        execute: async () => ({
          result: {
            nonce: spec.echoWrongNonce ? 'stale-wrong-nonce' : nonce,
            title: spec.title,
            claims: [claim],
          },
          stdout: '',
          stderr: '',
          exitCode: 0,
          durationMs: 5,
        }),
        close: async () => {},
      }
    },
  })

  // Clean matching dual-replay baseline MUST confirm
  const clean = await runDual(baseSpec, { ...baseSpec })
  assert.equal(clean.confirmed, true, `Matching dual-replay failed: ${clean.detail}`)
  assert.equal(clean.reason, 'confirmed')

  // Diverge route
  const diffRoute = await runDual(baseSpec, { ...baseSpec, route: '/api/v1/invoices/100' })
  assert.equal(diffRoute.confirmed, false)
  assert.equal(diffRoute.reason, 'transcript_mismatch')

  // Diverge HTTP method
  const diffMethod = await runDual(baseSpec, { ...baseSpec, method: 'PUT' })
  assert.equal(diffMethod.confirmed, false)
  assert.equal(diffMethod.reason, 'transcript_mismatch')

  // Diverge claim type (composite_receipt vs boundary)
  const diffClaimKind = await runDual(baseSpec, { ...baseSpec, claimKind: 'boundary' })
  assert.equal(diffClaimKind.confirmed, false)
  assert.equal(diffClaimKind.reason, 'transcript_mismatch')

  // Diverge terminal oracle family
  const diffFamily = await runDual(baseSpec, { ...baseSpec, oracleFamily: 'parser_cache_differential' })
  assert.equal(diffFamily.confirmed, false)
  assert.equal(diffFamily.reason, 'transcript_mismatch')

  // Diverge proof title
  const diffTitle = await runDual(baseSpec, { ...baseSpec, title: 'Different unrelated finding title' })
  assert.equal(diffTitle.confirmed, false)
  assert.equal(diffTitle.reason, 'transcript_mismatch')

  // Tampered signature on Run 2
  const badSig = await runDual(baseSpec, { ...baseSpec, tamperSig: true })
  assert.equal(badSig.confirmed, false)
  assert.equal(badSig.reason, 'transcript_mismatch')

  // Nonce mismatch on Run 2
  const badNonce = await runDual(baseSpec, { ...baseSpec, echoWrongNonce: true })
  assert.equal(badNonce.confirmed, false)
  assert.equal(badNonce.reason, 'nonce_mismatch')

  // Direct causalFingerprints unit check confirming distinct oracle family produces distinct fingerprint
  const s1 = new TranscriptStore()
  const c1: VerifyClaim = {
    kind: 'composite_receipt', chainId: 'ch-1', terminalVulnClass: 'dual_tenant_abac', exchangeIds: [],
    compositeReceipt: { terminalImpact: { oracleFamily: 'dual_tenant_abac' } },
  }
  const c2: VerifyClaim = {
    kind: 'composite_receipt', chainId: 'ch-1', terminalVulnClass: 'dual_tenant_abac', exchangeIds: [],
    compositeReceipt: { terminalImpact: { oracleFamily: 'economic_conservation' } },
  }
  const fp1 = causalFingerprints(s1, [{ claim: c1, passed: true, detail: 'ok' }], 'n1')[0]!
  const fp2 = causalFingerprints(s1, [{ claim: c2, passed: true, detail: 'ok' }], 'n2')[0]!
  assert.notEqual(JSON.stringify(fp1), JSON.stringify(fp2))
})

// ============================================================================
// 4. Live VerifyRpcServer End-to-End: Dirty Ablation + Zero Secret Leakage
// ============================================================================

test('M18 + Live RPC: Dirty post-mutation ablation rejected & zero raw secret leakage in RPC/redaction outputs', async (t) => {
  const PERSONA_SECRET = 'persona_live_secret_token_9182736455'
  const DERIVED_SECRET = 'derived_vault_secret_value_6677889900'
  const BEARER_RAW = 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig_raw_token_abcdef123456'
  const API_KEY_RAW = 'sk-or-v1-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'
  const PEM_RAW = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ==\n-----END PRIVATE KEY-----'

  const orderState = new Map<string, { primed: boolean }>()
  const app = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const json = (status: number, body: unknown, extraHeaders: Record<string, string> = {}) => {
      const text = JSON.stringify(body)
      res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text), ...extraHeaders })
      res.end(text)
    }
    if (url.pathname === '/api/leak-token' && req.method === 'GET') {
      return json(200, { token: DERIVED_SECRET, echoPersona: PERSONA_SECRET }, { 'x-leaked-bearer': BEARER_RAW })
    }
    if (url.pathname === '/api/orders/ord-9' && req.method === 'PATCH') {
      orderState.set('ord-9', { primed: true })
      return json(200, { id: 'ord-9', primed: true })
    }
    if (url.pathname === '/api/orders/ord-9/approve' && req.method === 'POST') {
      if (!orderState.get('ord-9')?.primed) return json(403, { error: 'unprimed' })
      return json(200, { id: 'ord-9', approved: true, payoutCents: 120000 })
    }
    return json(404, { error: 'not_found' })
  })
  const port = await new Promise<number>((resolve, reject) => {
    app.once('error', reject)
    app.listen(0, '127.0.0.1', () => {
      const addr = app.address()
      if (!addr || typeof addr === 'string') reject(new Error('no port'))
      else resolve(addr.port)
    })
  })
  const origin = `http://127.0.0.1:${port}`
  t.after(() => new Promise<void>(r => { app.closeAllConnections(); app.close(() => r()) }))

  const persona: ResolvedPersona = {
    id: 'p-member-alpha',
    handle: 'member_alpha',
    roleLabel: 'member (org-alpha)',
    originAllowlist: [origin],
    authKind: 'header',
    headerName: 'X-Session-Auth',
    secret: PERSONA_SECRET,
    canaryMarkers: [],
  }
  const grant: Grant = {
    origin,
    tier: 3,
    allowLocalLab: true,
    allowedPorts: [port],
    maxRpsPerOrigin: 200,
    personas: new Map([['member_alpha', persona]]),
    canRead: cand => cand === origin,
    isStateChangeApproved: () => true,
    audit: () => {},
  }
  const server = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant,
    runId: `run-fuzz-${randomUUID().slice(0, 8)}`,
    assignmentId: 'assign-fuzz',
    targetOrigins: [origin],
  })
  await server.start()
  t.after(() => server.close())

  const rpc = (op: string, args: Record<string, unknown>) => new Promise<{ ok: boolean; result?: Record<string, unknown>; error?: string }>((resolve, reject) => {
    const payload = JSON.stringify({ op, args })
    const req = httpRequest({
      socketPath: server.socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        [VERIFY_RPC_HEADER]: server.token,
        [VERIFY_NONCE_HEADER]: server.nonce,
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
      },
    }, res => {
      let data = ''
      res.on('data', chunk => { data += chunk })
      res.on('end', () => resolve(JSON.parse(data) as { ok: boolean; result?: Record<string, unknown>; error?: string }))
    })
    req.on('error', reject)
    req.end(payload)
  })

  // 1) Live dirty post-mutation ablation on same entity MUST be stamped cleanSession=false and rejected
  const hop1 = await rpc('http.send', { method: 'PATCH', path: '/api/orders/ord-9', as: 'member_alpha', arm: 'probe', entityId: 'ord-9' })
  assert.equal(hop1.ok, true)
  const hop2 = await rpc('http.send', { method: 'POST', path: '/api/orders/ord-9/approve', as: 'member_alpha', arm: 'probe', entityId: 'ord-9' })
  assert.equal(hop2.ok, true)
  const dirtyAbl = await rpc('http.send', { method: 'POST', path: '/api/orders/ord-9/approve', as: 'member_alpha', arm: 'control', replayAttempt: 'ablation_control', entityId: 'ord-9' })
  assert.equal(dirtyAbl.ok, true)
  const dirtyVerdict = await rpc('composite.verify', {
    chainId: 'chain-rpc-dirty-ablation',
    terminalVulnClass: 'business_logic',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin, method: 'PATCH', pathAndQuery: '/api/orders/ord-9' }, exchangeIds: [hop1.result!.exchangeId], entityId: 'ord-9', claimedDelta: 'Primed order' },
      { hopId: 'h2', surface: 'http', target: { origin, method: 'POST', pathAndQuery: '/api/orders/ord-9/approve' }, exchangeIds: [hop2.result!.exchangeId], entityId: 'ord-9', claimedDelta: 'Approved order' },
    ],
    causalEdges: [{ kind: 'state_transition_binding', fromHopId: 'h1', toHopId: 'h2', entityId: 'ord-9', ablationExchangeIds: [dirtyAbl.result!.exchangeId] }],
    terminalImpact: { terminalHopId: 'h2', summary: 'Dirty post-mutation ablation must never pass verification.', terminalExchangeId: hop2.result!.exchangeId },
  })
  assert.equal(dirtyVerdict.ok, true)
  assert.equal(dirtyVerdict.result!.confirmed, false)
  assert.equal(dirtyVerdict.result!.failedStage, 'edge_binding')

  // 2) Secret scrubbing on HTTP responses, capability.seal, transcript.get, and composite.verify RPC output
  const leakEx = await rpc('http.send', { method: 'GET', path: '/api/leak-token', as: 'member_alpha', arm: 'probe' })
  assert.equal(leakEx.ok, true)
  const leakExJson = JSON.stringify(leakEx)
  assert.equal(leakExJson.includes(PERSONA_SECRET), false, 'Persona secret leaked in http.send response')
  assert.equal(leakExJson.includes('sig_raw_token_abcdef123456'), false, 'Bearer JWT leaked in http.send response headers')

  const sealed = await rpc('capability.seal', { exchangeId: leakEx.result!.exchangeId, slot: 'tok', jsonPath: '$.token' })
  assert.equal(sealed.ok, true)
  assert.equal(JSON.stringify(sealed).includes(DERIVED_SECRET), false, 'Derived secret leaked in capability.seal response')

  const trGet = await rpc('transcript', { action: 'get', exchangeId: leakEx.result!.exchangeId })
  assert.equal(trGet.ok, true)
  const trGetJson = JSON.stringify(trGet)
  assert.equal(trGetJson.includes(PERSONA_SECRET), false, 'Persona secret leaked in transcript.get')
  assert.equal(trGetJson.includes(DERIVED_SECRET), false, 'Derived secret leaked in transcript.get after retroactive rescrub')

  // Embed PERSONA_SECRET and DERIVED_SECRET in chainId + summary passed to composite.verify -> RPC response MUST scrub both!
  const compWithSecrets = await rpc('composite.verify', {
    chainId: `chain-${PERSONA_SECRET}-${DERIVED_SECRET}`,
    terminalVulnClass: 'business_logic',
    hops: [{ hopId: 'h1', surface: 'http', target: { origin, pathAndQuery: '/api/orders/ord-9' }, exchangeIds: ['gx-missing'], claimedDelta: `delta ${PERSONA_SECRET}` }],
    terminalImpact: { terminalHopId: 'h1', summary: `summary containing ${DERIVED_SECRET} and ${PERSONA_SECRET}` },
  })
  const compJson = JSON.stringify(compWithSecrets)
  assert.equal(compJson.includes(PERSONA_SECRET), false, 'Persona secret leaked in composite.verify RPC response')
  assert.equal(compJson.includes(DERIVED_SECRET), false, 'Derived secret leaked in composite.verify RPC response')

  // 3) DerivedCapabilityVault variant scrubbing (raw, URL-encoded, Base64, Base64URL)
  const vault = new DerivedCapabilityVault({ runId: 'run-scrub-fuzz' })
  vault.seal({ hopReceiptId: 'h1', slot: 'api_key', rawValue: DERIVED_SECRET })
  const variants = [
    DERIVED_SECRET,
    encodeURIComponent(DERIVED_SECRET),
    Buffer.from(DERIVED_SECRET, 'utf8').toString('base64'),
    Buffer.from(DERIVED_SECRET, 'utf8').toString('base64url'),
  ]
  for (const variant of variants) {
    const scrubbed = scrubDerivedSecrets(`err: leaked=${variant}`, vault)
    assert.equal(scrubbed.includes(variant), false, `Derived secret variant leaked after scrubDerivedSecrets: ${variant.slice(0, 8)}`)
  }

  // 4) Generic redaction of Bearer / API key / JWT / PEM in headers, JSON, and verifyScript stderr
  const redactedHeaders = redactHeaders({ Authorization: BEARER_RAW, 'X-Debug': `${API_KEY_RAW} ${PERSONA_SECRET}` }, [{ value: PERSONA_SECRET, placeholder: '[redacted:p]' }])
  for (const needle of [PERSONA_SECRET, API_KEY_RAW, 'sig_raw_token_abcdef123456']) {
    assert.equal(JSON.stringify(redactedHeaders).includes(needle), false, `Secret leaked in redactHeaders: ${needle.slice(0, 12)}`)
  }
  const redactedObj = redactJsonValue({ chainId: `ch-${API_KEY_RAW}`, title: `T ${BEARER_RAW}`, err: PEM_RAW, token: DERIVED_SECRET })
  for (const needle of [API_KEY_RAW, 'sig_raw_token_abcdef123456', 'MIIEvQIBADANBgkqhkiG9w0', DERIVED_SECRET]) {
    assert.equal(JSON.stringify(redactedObj).includes(needle), false, `Secret leaked in redactJsonValue: ${needle.slice(0, 12)}`)
  }
  const redactedText = redact(`chain=${API_KEY_RAW} auth=${BEARER_RAW} key=${PEM_RAW}`)
  for (const needle of [API_KEY_RAW, 'sig_raw_token_abcdef123456', 'MIIEvQIBADANBgkqhkiG9w0']) {
    assert.equal(redactedText.includes(needle), false)
  }

  // verifyScript stderr redaction check
  const errVerdict = await verifyScript({
    candidate: { name: 'stderr-redact', runtime: 'ts', code: '' },
    openAttempt: async ({ nonce }) => ({
      nonce,
      transcript: new TranscriptStore(),
      execute: async () => ({
        result: { error: `boom ${BEARER_RAW} ${API_KEY_RAW}` },
        stdout: '',
        stderr: `trace ${PEM_RAW} ${BEARER_RAW} ${API_KEY_RAW}`,
        exitCode: 1,
        durationMs: 3,
      }),
      close: async () => {},
    }),
  })
  assert.equal(errVerdict.confirmed, false)
  const errVerdictStr = JSON.stringify(errVerdict)
  for (const needle of [API_KEY_RAW, 'sig_raw_token_abcdef123456', 'MIIEvQIBADANBgkqhkiG9w0']) {
    assert.equal(errVerdictStr.includes(needle), false, `Raw secret leaked in verifyScript error verdict: ${needle.slice(0, 12)}`)
  }
})

// ============================================================================
// 5. Seeded Deterministic Randomized Adversarial Mutation Fuzzer (240 trials)
// ============================================================================

function mulberry32(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6D2B79F5) >>> 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

interface MutatorDef {
  id: string
  applicable: (b: BaselineFixture) => boolean
  apply: (r: CompositeProofReceipt, t: HostSignedTranscript, opts: CompositeVerifyOptions, rng: () => number) => { reSign: boolean }
}

const FUZZ_MUTATORS: readonly MutatorDef[] = [
  {
    id: 'tamper_entry_signature',
    applicable: b => (b.transcript.entries?.length ?? 0) > 0,
    apply: (_r, t, _o, rng) => {
      const idx = Math.floor(rng() * t.entries!.length)
      const sig = t.entries![idx]!.hostSignature ?? 'a'.repeat(64)
      t.entries![idx]!.hostSignature = (sig[0] === '0' ? '1' : '0') + sig.slice(1)
      return { reSign: false }
    },
  },
  {
    id: 'wrong_signing_key',
    applicable: () => true,
    apply: (_r, _t, o) => {
      o.signingKey = 'wrong-signing-key-' + createHash('sha256').update('fuzz').digest('hex').slice(0, 12)
      return { reSign: false }
    },
  },
  {
    id: 'orphan_hop',
    applicable: () => true,
    apply: (r) => {
      r.hops.push({
        hopId: `hop_orphan_${r.hops.length}`,
        surface: 'http',
        target: { origin: ORIGIN_API, pathAndQuery: '/api/orphan' },
        exchangeIds: [r.hops[0]!.exchangeIds[0]!],
        oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Disconnected hop',
        producedCapabilities: [], consumedCapabilities: [],
      })
      return { reSign: true }
    },
  },
  {
    id: 'duplicate_hop_id',
    applicable: () => true,
    apply: (r) => {
      r.hops.push(deepClone(r.hops[0]!))
      return { reSign: true }
    },
  },
  {
    id: 'empty_hops',
    applicable: () => true,
    apply: (r) => {
      r.hops = []
      return { reSign: true }
    },
  },
  {
    id: 'dag_cycle_or_self_loop',
    applicable: () => true,
    apply: (r) => {
      const a = r.hops[0]!.hopId
      const b = r.hops[r.hops.length - 1]!.hopId
      r.causalEdges.push({ kind: 'value_binding', fromHopId: b, toHopId: a, capabilityHandle: 'cap:hop_1:loop' })
      return { reSign: true }
    },
  },
  {
    id: 'unknown_terminal_hop',
    applicable: () => true,
    apply: (r) => {
      r.terminalImpact.terminalHopId = 'hop_unknown_999'
      return { reSign: true }
    },
  },
  {
    id: 'missing_cited_exchange',
    applicable: () => true,
    apply: (r) => {
      r.hops[0]!.exchangeIds.push('gx-nonexistent-fuzz-id')
      return { reSign: true }
    },
  },
  {
    id: 'forbidden_shortcut_persona',
    applicable: b => (b.transcript.entries ?? []).some(e => e.step.arm === 'probe'),
    apply: (_r, t) => {
      const probe = t.entries!.find(e => e.step.arm === 'probe')!
      probe.actorPersona = 'admin_beta'
      probe.step.actor = { handle: 'admin_beta', role: 'admin', tenant: 'org-beta', auth: 'bearer', sameSite: null }
      return { reSign: true }
    },
  },
  {
    id: 'dirty_mode_a_session',
    applicable: b => (b.transcript.entries ?? []).some(e => e.step.arm === 'probe'),
    apply: (_r, t) => {
      const probe = t.entries!.find(e => e.step.arm === 'probe')!
      probe.cleanSession = false
      return { reSign: true }
    },
  },
  {
    id: 'downgrade_to_invalid_mode_b',
    applicable: () => true,
    apply: (r) => {
      r.replayMode = 'one_shot_transcript'
      delete r.terminalImpact.modeAFailureExchangeId
      return { reSign: true }
    },
  },
  {
    id: 'short_empty_terminal_summary',
    applicable: () => true,
    apply: (r) => {
      r.terminalImpact.summary = 'short'
      r.terminalImpact.claimedImpact = 'short'
      return { reSign: true }
    },
  },
  {
    id: 'reverse_edge_timestamps',
    applicable: b => b.receipt.causalEdges.length > 0 && b.receipt.hops.length >= 2,
    apply: (r, t) => {
      const edge = r.causalEdges[0]!
      const fromHop = r.hops.find(h => h.hopId === edge.fromHopId)!
      const toHop = r.hops.find(h => h.hopId === edge.toHopId)!
      for (const id of fromHop.exchangeIds) {
        const e = t.entries!.find(x => x.exchangeId === id)
        if (e) e.timestampMs = 99_999
      }
      for (const id of toHop.exchangeIds) {
        const e = t.entries!.find(x => x.exchangeId === id)
        if (e) e.timestampMs = 500
      }
      return { reSign: true }
    },
  },
  {
    id: 'ablation_returns_200',
    applicable: b => b.receipt.causalEdges.some(e => e.kind === 'state_transition_binding'),
    apply: (r, t) => {
      const edge = r.causalEdges.find(e => e.kind === 'state_transition_binding')!
      const ab = t.entries!.find(e => e.exchangeId === edge.ablationExchangeIds[0])!
      ab.step.status = 200
      return { reSign: true }
    },
  },
  {
    id: 'ablation_dirty_post_mutation',
    applicable: b => b.receipt.causalEdges.some(e => e.kind === 'state_transition_binding'),
    apply: (r, t) => {
      const edge = r.causalEdges.find(e => e.kind === 'state_transition_binding')!
      const ab = t.entries!.find(e => e.exchangeId === edge.ablationExchangeIds[0])!
      ab.cleanSession = false
      return { reSign: true }
    },
  },
  {
    id: 'break_value_binding_cap',
    applicable: b => b.receipt.causalEdges.some(e => e.kind === 'value_binding' && e.capabilityHandle),
    apply: (_r, t) => {
      for (const e of t.entries ?? []) e.consumedCapabilities = []
      return { reSign: true }
    },
  },
  {
    id: 'forge_crypto_attestation_digest',
    applicable: b => b.receipt.causalEdges.some(e => e.kind === 'derived_crypto_binding'),
    apply: (_r, t) => {
      for (const e of t.entries ?? []) {
        for (const att of e.cryptoAttestations ?? []) att.artifactDigest = 'forged-non-hex-digest'
      }
      return { reSign: true }
    },
  },
  {
    id: 'replace_terminal_with_queued_stub',
    applicable: b => !b.name.startsWith('edge:async_pivot_binding') && b.name !== 'oracle:economic_conservation' && b.name !== 'edge:state_transition_binding' && b.name !== 'oracle:temporal_revocation',
    apply: (r, t) => {
      const termId = r.terminalImpact.terminalExchangeId
      const term = t.entries!.find(e => e.exchangeId === termId)
      if (term) {
        term.step.status = 202
        term.step.json = { jobId: 'job-stub-999', status: 'queued' }
        term.step.body = undefined
        term.observedResponseDigests = []
      }
      return { reSign: true }
    },
  },
  {
    id: 'cross_tenant_probe_collusion',
    applicable: b => b.receipt.hops.length >= 2 && (b.transcript.entries ?? []).filter(e => e.step.arm === 'probe').length >= 2,
    apply: (_r, t, o) => {
      const probes = t.entries!.filter(e => e.step.arm === 'probe')
      probes[probes.length - 1]!.actorPersona = 'member_beta'
      probes[probes.length - 1]!.actorRoleLabel = 'member (org-beta)'
      probes[probes.length - 1]!.step.actor = { handle: 'member_beta', role: 'member', tenant: 'org-beta', auth: 'bearer', sameSite: null }
      o.attackerPersonas = ['member_alpha', 'member_beta']
      return { reSign: true }
    },
  },
  {
    id: 'strip_pre_chain_control',
    applicable: b => b.receipt.terminalImpact.preChainControlExchangeIds.length > 0 && b.name !== 'edge:state_transition_binding' && b.name !== 'oracle:economic_conservation',
    apply: (r, t) => {
      for (const id of r.terminalImpact.preChainControlExchangeIds) {
        const e = t.entries!.find(x => x.exchangeId === id)
        if (e) e.step.status = 200
      }
      return { reSign: true }
    },
  },
]

test('Seeded randomized adversarial fuzzer (260 mutation trials across all baselines): 100% fail-closed & 0 signingKey leaks', () => {
  const SEED = 0x5EED_0803
  const RANDOM_TRIALS = 240
  const rng = mulberry32(SEED)
  const baselines = buildAllBaselines()
  const mutatorHits = new Map<string, number>()

  const runTrial = (label: string, base: BaselineFixture, mutators: readonly MutatorDef[]) => {
    const receipt = deepClone(base.receipt)
    let transcript = deepClone(base.transcript)
    const options: CompositeVerifyOptions = { ...base.options }
    let shouldReSign = true
    for (const mut of mutators) {
      mutatorHits.set(mut.id, (mutatorHits.get(mut.id) ?? 0) + 1)
      const { reSign } = mut.apply(receipt, transcript, options, rng)
      if (!reSign) shouldReSign = false
    }
    if (shouldReSign) transcript = signTranscript(transcript)
    const verdict = verifyCompositeReceipt(receipt, transcript, options)
    assert.equal(
      verdict.confirmed,
      false,
      `FAIL-OPEN on ${label} baseline=${base.name} mutators=[${mutators.map(m => m.id).join(',')}] reason=${verdict.reason}`,
    )
    assert.ok(verdict.failedStage, `Missing failedStage on ${label}`)
    assertNoSigningKeyLeak(verdict)
  }

  // Deterministic coverage sweep: guarantee every mutator is exercised on a compatible baseline
  for (const mut of FUZZ_MUTATORS) {
    const compatible = baselines.filter(b => mut.applicable(b))
    assert.ok(compatible.length > 0, `No compatible baseline for mutator "${mut.id}"`)
    runTrial(`sweep:${mut.id}`, compatible[0]!, [mut])
  }

  // 240 seeded randomized single- and multi-mutation trials across all baselines
  for (let trial = 0; trial < RANDOM_TRIALS; trial += 1) {
    const base = baselines[Math.floor(rng() * baselines.length)]!
    const applicable = FUZZ_MUTATORS.filter(m => m.applicable(base))
    assert.ok(applicable.length > 0)
    const numMutations = rng() < 0.7 ? 1 : 2
    const chosen: MutatorDef[] = []
    for (let k = 0; k < numMutations; k += 1) {
      chosen.push(applicable[Math.floor(rng() * applicable.length)]!)
    }
    runTrial(`seed=${SEED}#${trial}`, base, chosen)
  }

  // Verify every single mutator in the catalog was exercised
  for (const mut of FUZZ_MUTATORS) {
    assert.ok((mutatorHits.get(mut.id) ?? 0) > 0, `Fuzz mutator "${mut.id}" was never exercised`)
  }
})
